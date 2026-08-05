package telnet

import (
	"io"
	"net"
	"strings"
	"time"
)

const EmptyReadRetryDelay = 100 * time.Millisecond

const maxNegotiationRounds = 8

type BannerResult struct {
	Raw []byte

	Visible []byte

	Annotated string

	HasIAC bool

	SentEnter bool

	Will []byte
	Wont []byte
	Do   []byte
	Dont []byte
}

func ReadBannerWithNegotiate(conn net.Conn, timeout time.Duration) BannerResult {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	var res BannerResult
	buf := make([]byte, 4096)
	var visible []byte
	var annotated strings.Builder

	perRead := func() time.Duration {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 100 * time.Millisecond
		}
		if remaining/2 < 200*time.Millisecond {
			return remaining
		}
		return remaining / 2
	}

	readOnce := func(budget time.Duration) (int, error) {
		_ = conn.SetReadDeadline(time.Now().Add(budget))
		return conn.Read(buf)
	}

	for range maxNegotiationRounds {
		if time.Now().After(deadline) {
			break
		}
		n, err := readOnce(perRead())
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			res.Raw = append(res.Raw, chunk...)
			ir := ParseIAC(chunk)
			visible = append(visible, ir.Visible...)
			annotated.WriteString(ir.Annotated)
			if ir.HasIAC {
				res.HasIAC = true
			}
			res.Will = mergeOptions(res.Will, ir.Will)
			res.Wont = mergeOptions(res.Wont, ir.Wont)
			res.Do = mergeOptions(res.Do, ir.Do)
			res.Dont = mergeOptions(res.Dont, ir.Dont)
			if len(ir.Responses) > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(perRead()))
				_, werr := conn.Write(ir.Responses)
				if werr != nil {
					break
				}

				continue
			}

			if len(visible) > 0 {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			break
		}
	}

	if len(visible) == 0 {
		remaining := time.Until(deadline)
		if remaining > EmptyReadRetryDelay+100*time.Millisecond {
			_ = conn.SetWriteDeadline(time.Now().Add(perRead()))
			if _, werr := conn.Write([]byte("\r\n")); werr == nil {
				res.SentEnter = true
				time.Sleep(EmptyReadRetryDelay)
				n, _ := readOnce(perRead())
				if n > 0 {
					chunk := append([]byte(nil), buf[:n]...)
					res.Raw = append(res.Raw, chunk...)
					ir := ParseIAC(chunk)
					visible = append(visible, ir.Visible...)
					annotated.WriteString(ir.Annotated)
					if ir.HasIAC {
						res.HasIAC = true
					}
					res.Will = mergeOptions(res.Will, ir.Will)
					res.Wont = mergeOptions(res.Wont, ir.Wont)
					res.Do = mergeOptions(res.Do, ir.Do)
					res.Dont = mergeOptions(res.Dont, ir.Dont)
					if len(ir.Responses) > 0 {
						_ = conn.SetWriteDeadline(time.Now().Add(perRead()))
						_, _ = conn.Write(ir.Responses)
					}
				}
			}
		}
	}

	res.Visible = visible
	res.Annotated = annotated.String()
	return res
}

func ReadBannerPassive(conn net.Conn, timeout time.Duration) BannerResult {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	var res BannerResult
	buf := make([]byte, 4096)
	var visible []byte
	var annotated strings.Builder

	for range maxNegotiationRounds {
		budget := time.Until(deadline)
		if budget <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(budget))
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			res.Raw = append(res.Raw, chunk...)
			ir := ParseIAC(chunk)
			visible = append(visible, ir.Visible...)
			annotated.WriteString(ir.Annotated)
			if ir.HasIAC {
				res.HasIAC = true
			}
			res.Will = mergeOptions(res.Will, ir.Will)
			res.Wont = mergeOptions(res.Wont, ir.Wont)
			res.Do = mergeOptions(res.Do, ir.Do)
			res.Dont = mergeOptions(res.Dont, ir.Dont)
			if len(visible) > 0 {
				break
			}
		}
		if err != nil {
			break
		}
	}

	res.Visible = visible
	res.Annotated = annotated.String()
	return res
}

func SendEnterAndRead(conn net.Conn, timeout time.Duration) []byte {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return nil
	}
	time.Sleep(EmptyReadRetryDelay)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func mergeOptions(dst, src []byte) []byte {
	if len(src) == 0 {
		return dst
	}
	for _, v := range src {
		dst = appendUnique(dst, v)
	}
	return dst
}
