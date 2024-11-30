@load base/protocols/ssh

global auth_failed_table: table[addr, addr] of count &default = 0;

event ssh_auth_attempted(c: connection, authenticated: bool) {
    local dst = c$id$resp_h;
    local src = c$id$orig_h;

    const max_attempts = 20;

    # Increment the count of failed attempts for the source and destination IP pair in the table
    auth_failed_table[src, dst] += 1;

    # If authentication attempt is not successful and reached the max allowed attempts, print a log message for detection
    if (!authenticated && auth_failed_table[src, dst] >= max_attempts) {
        print fmt("Potential SSH brute force attempt detected from %s to %s (Attempt %d) - Sreyash Mohanty, RollNo. CS23MTECH14015", src, dst, auth_failed_table[src, dst]);
    }
}

