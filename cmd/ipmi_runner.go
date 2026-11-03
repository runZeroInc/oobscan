package cmd

// Shared execution scaffolding for every command that drives a BMC over IPMI.
//
// `ipmi` and the top-level `smc-*` commands all expand a target list, open a
// session per target, run one workflow and render the result. That loop, the
// progress spinner, the failure accounting and the session options live here so
// each command supplies only its own step.

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// ipmiSessionOptions builds the session options from the shared flags. Every
// command that opens a session gets the same negotiation and bypass behavior.
func ipmiSessionOptions(host string) ipmi.CmdSessOptions {
	return ipmi.CmdSessOptions{
		Host:              host,
		Port:              ipmiPort,
		Username:          ipmiUser,
		Password:          ipmiPassword,
		Timeout:           ipmiTimeout,
		MaxRetries:        ipmiMaxRetries,
		IPMIVersion:       ipmiVersion,
		Auth:              ipmiAuth,
		Cipher:            ipmiCipher,
		DisableSMCRAKP:    ipmiDisableSMCRAKP,
		ForceSMCRAKP:      ipmiForceSMCRAKP,
		CommandProtection: ipmiProto,
		OpenBMCRelabel:    ipmiOpenBMCRelabel,
		OpenBMCBMCRand:    ipmiOpenBMCBMCRand,
		OpenBMCBypassFast: ipmiOpenBMCBypass,
		OpenBMCFastRounds: ipmiOpenBMCRounds,
		ILORAKPNone:       ipmiILORAKPNone,
	}
}

// ipmiStepError tags a failure with the stage it happened in, so every command
// reports "[host] session error: ..." and "[host] command error: ..." the same
// way without each step reaching for the spinner.
type ipmiStepError struct {
	stage string
	err   error
}

func (e *ipmiStepError) Error() string { return e.err.Error() }
func (e *ipmiStepError) Unwrap() error { return e.err }

func stepErrorf(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &ipmiStepError{stage: stage, err: err}
}

// ipmiTargetStep runs one command against one target. Returning an error marks
// that target failed; the loop owns the tally and the closing summary.
type ipmiTargetStep func(ctx context.Context, idx int, host string, status *ipmiStatusSpinner) error

// runIPMITargets drives step across every target. label names the command in
// the progress line and the failure summary; usage is printed once at the end if
// any failure looked like a bad argument rather than an unreachable target.
func runIPMITargets(cmd *cobra.Command, targets []string, label string, usage func(), step ipmiTargetStep) error {
	out := cmd.OutOrStdout()
	status := newIPMIStatusSpinner(cmd.ErrOrStderr(), len(targets), label)
	status.Start()
	defer status.Stop("")

	ctx := context.Background()
	failures, validationErrs := 0, 0
	for i, host := range targets {
		status.Set(i+1, host, "starting")
		err := step(ctx, i+1, host, status)
		if err == nil {
			status.Set(i+1, host, "done")
			continue
		}
		failures++
		if isIPMICommandValidationError(err.Error()) {
			validationErrs++
		}
		stage := "command"
		var se *ipmiStepError
		if ok := asStepError(err, &se); ok && se.stage != "" {
			stage = se.stage
		}
		status.WithPaused(func() {
			fmt.Fprintf(out, "[%s] %s error: %v\n", host, stage, err)
		})
	}
	if failures > 0 {
		status.Stop(fmt.Sprintf("%s finished: %d/%d target(s) failed", label, failures, len(targets)))
		if validationErrs > 0 && usage != nil {
			status.WithPaused(usage)
		}
		status.WithPaused(func() {
			fmt.Fprintf(out, "%s: %d target(s) failed\n", label, failures)
		})
		return nil
	}
	status.Stop(fmt.Sprintf("%s finished: %d target(s) ok", label, len(targets)))
	return nil
}

// asStepError is errors.As specialized to *ipmiStepError, kept local so the
// loop reads as one expression.
func asStepError(err error, target **ipmiStepError) bool {
	for err != nil {
		if se, ok := err.(*ipmiStepError); ok {
			*target = se
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// runIPMISessionStep is the step every session-backed command shares: open the
// session, run fn, render the result, close. Commands differ only in fn.
func runIPMISessionStep(cmd *cobra.Command, args []string, fn ipmiSessionFunc) ipmiTargetStep {
	return func(ctx context.Context, idx int, host string, status *ipmiStatusSpinner) error {
		status.Set(idx, host, "opening session")
		sess, err := ipmi.OpenCmdSess(ipmiSessionOptions(host))
		if err != nil {
			status.Set(idx, host, "session failed")
			return stepErrorf("session", err)
		}
		defer sess.Close()
		if sess.SMCRAKPDetected() {
			status.WithPaused(func() {
				log().Warnf("[%s] Hardcoded SMCRAKP RAKP key detected, passwords may be optional...", host)
			})
		}

		status.Set(idx, host, "running command")
		commandCtx := ipmi.WithCommandProgress(ctx, func(update string) {
			status.Set(idx, host, update)
		})
		res, err := fn(commandCtx, sess, args)
		if err != nil {
			status.Set(idx, host, "command failed")
			return stepErrorf("command", err)
		}

		status.Set(idx, host, "rendering output")
		var printErr error
		status.WithPaused(func() {
			printErr = printIPMIResult(cmd, host, sess, res)
		})
		if printErr != nil {
			status.Set(idx, host, "output failed")
			return stepErrorf("output", printErr)
		}
		return nil
	}
}

// ipmiSessionFunc is one workflow run against an open session.
type ipmiSessionFunc func(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error)

// validateIPMIOutputFlags checks the flags that are meaningless to defer to a
// live target, so a typo fails before any packet goes out.
func validateIPMIOutputFlags() error {
	if !isSupportedIPMIFormat(ipmiOutputFormat) {
		return fmt.Errorf("unsupported --format %q (use table, json, jsonl, or ndjson)", ipmiOutputFormat)
	}
	if ipmiMaxRetries < 1 {
		return fmt.Errorf("invalid --max-retries %d (use 1 or greater)", ipmiMaxRetries)
	}
	return nil
}

// isIPMICommandValidationError reports whether a failure came from the
// arguments rather than the target, in which case the caller reprints usage.
func isIPMICommandValidationError(msg string) bool {
	msg = strings.ToLower(strings.TrimSpace(msg))
	switch {
	case strings.Contains(msg, "usage:"),
		strings.Contains(msg, "required"),
		strings.Contains(msg, "unsupported --"),
		strings.HasPrefix(msg, "unsupported "),
		strings.HasPrefix(msg, "invalid "):
		return true
	}
	return false
}
