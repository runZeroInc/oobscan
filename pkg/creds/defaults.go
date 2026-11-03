// Package creds ships the built-in BMC/Redfish credential wordlists, drawn from
// vendor docs and first-boot UX, public default-credential collections (SecLists,
// SCADA-StrangeLove, DefPass) cross-checked against those docs, and weak
// credentials observed against BMC logins.
//
// Callers should iterate these rather than slice them directly, so a later
// addition does not break an ordering assumption.
package creds

// CommonUsernames is the default username pool tried via RAKP. The first 20
// entries are exactly the runZero platform IPMI probe's list, in its order
// (runzero/protocols/ipmi/rakp.go), so oobscan enumerates the same accounts;
// the trailing entries are BMC-specific extras this repo adds.
var CommonUsernames = []string{
	// --- identical to platform probe_ipmi.go CommonUsernames ---
	"ADMIN",         // Most common Supermicro default (case-sensitive)
	"admin",         // Lowercase variant
	"Admin",         // Capitalized variant (common on many BMCs)
	"root",          // Common on many systems, Dell iDRAC, OpenBMC
	"USERID",        // IBM / Lenovo IMM default
	"Administrator", // HPE iLO, Windows-style
	"administrator", // Lowercase variant
	"guest",         // Guest account
	"default",       // Factory default account
	"anonymous",     // Anonymous access
	"sysadmin",      // AMI MegaRAC UID-0 / Fujitsu iRMC / Quanta
	"operator",      // Operator role
	"supervisor",    // Supervisor role
	"service",       // Service account
	"test",          // Test/QA leftover
	"support",       // Support account
	"monitor",       // Monitoring account
	"user",          // Generic user
	"avid",          // Avid default
	"",              // Anonymous/null username
	// --- oobscan extras (not in the platform list) ---
	"user1",    // Dell iDRAC firmware-seeded secondary account (user1:user1234)
	"bmc",      // OpenBMC sample configs
	"manager",  // some OEM BMCs
	"ipmi",     // dev/test firmware
	"fwupd",    // OpenBMC fwupd firmware-update daemon auto-creates this IPMI account (fwupd/fwupd#6381)
	"fbuser",   // Commonly observed
	"system",   // generic service slot (Supermicro/Lenovo)
	"sim",      // reference/simulation firmware account
	"Operator", // HPE iLO factory account-slot name (capitalized; "operator" already covers lowercase)
	"OEM",      // HPE iLO reserved OEM account-slot name
	"yfadmin",  // enabled Huawei iBMC admin account
	"ydview",   // Huawei iBMC view account
	// --- additional generic account names observed in post-auth Get User Name enumeration ---
	"Callback",  // IPMI standard channel account-slot name (case-sensitive)
	"User",      // capitalized generic slot ("user" already covers lowercase; RAKP is case-sensitive)
	"IPMI_USER", // generic BMC service account; distinct owners
	"test1",     // sequential QA-leftover accounts, seen together on multiple hosts
	"test2",     //
	"test3",     //
	// --- documented / widely-used defaults confirmed via vendor docs + web research ---
	"openbmc",    // OpenBMC dev/CI default account (openbmc:0penBmc$) per OpenBMC user-management design doc
	"bmcroot",    // OpenBMC/HPE-derived root-style account; observed on an HPE host
	"monitoring", // dedicated restricted IPMI monitoring user (Nagios/Icinga/Thomas-Krenn setups)
	"nagios",     // monitoring-tool service account commonly reused for IPMI sensor polling
	"icinga",     // monitoring-tool service account
	"zabbix",     // monitoring-tool service account (Zabbix IPMI monitoring)
}

// DefaultPasswords is the vendor default password pool, tried before the wider
// CommonPasswords spray. Merged from the in-repo list and the runZero platform
// IPMI probe; vendor-specific pairings live in Table.
var DefaultPasswords = []string{
	"ADMIN",                  // Supermicro ATEN
	"admin",                  // generic
	"calvin",                 // Dell iDRAC
	"password",               // HP iLO2 factory some SKUs / generic / Cisco CIMC
	"PASSW0RD",               // IBM IMM (zero, not O)
	"Passw0rd",               // Lenovo XCC / IBM IMM
	"superuser",              // AMI MegaRAC UID-0 / Inspur / Quanta support
	"supperuser",             // Inspur typo variant seen in the wild
	"0penBmc",                // OpenBMC phosphor reference
	"Huawei12#$",             // Huawei iBMC
	"computer1",              // Dell observed
	"4rfv$RFV",               // Supermicro IPMI
	"DefaultFactoryPassword", // Dell iDRAC secure-default
	"advantech",              // Advantech
	"Admin@9000",             // Advantech
	"adminadmin",             // Quanta/QCT
	"ipmitool",               // ipmitool docs default
	"Avid123",                // Avid
	"Avid123!",               // Avid
	"public",                 // SNMP-y default occasionally reused
	"Password123",            // Intel ME reference docs
	"root",                   // generic
	"unique",                 // older ASRockRack default
	"",                       // blank - surprisingly common on lab firmware
	"changeme",               // Oracle ILOM
	"changeme!",              //
	"Administrator",          //
	"bmc",                    //
	"ipmi",                   //
	"test",                   //
	"guest",                  //
	"manager",                //
	"operator",               //
	"support",                //
	"factorypasswd",          //
	"welcome",                //
	"welcome1",               //
}

// CommonPasswords lists frequently observed weak passwords tried after the
// vendor defaults. Ported from the runZero platform IPMI probe.
var CommonPasswords = []string{
	"", "admin", "Admin", "admin123", "Admin123", "password", "Password",
	"Password1", "P@ssw0rd", "passw0rd", "root", "changeme", "default",
	"1234", "12345", "123456", "12345678", "qwerty", "letmein", "welcome",
	"test", "guest", "operator", "supervisor", "public", "private", "access",
	"server", "super", "manage",
}

// VendorPairs (the short, high-signal list of vendor-specific first-boot
// defaults) is now derived from Table in select.go - edit Table to change it.
