@load base/protocols/ssl

event ssl_established(c: connection) {
    local dst_ip = c$id$resp_h;

    if (c$ssl$issuer == c$ssl$subject) {
        print fmt("Self-signed certificate detected for website with IP address %s", dst_ip);
    }
}

