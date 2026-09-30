# Docker Netfilter Firewall Operator

This is _another_ operator script, similar to those such as:

- [Whalewall](https://github.com/capnspacehook/whalewall)
- [Docker Firewall Operator](https://github.com/hit2hat/docker-firewall)
- [DCFW](https://github.com/dimajix/dcfw)
- [Docker Firewall](https://github.com/ftoppi/docker-firewall)

What's different? The three things I wanted to do were:

1. Use `netfilter` rather than `iptables`
2. Give label-level access to express `netfilter` rules rully
3. Apply rules inside the network namespace of containers, mainly to overcome host-based filtering limitations on macvlan networks

If this combination doesn't suit you, check out the above alternatives, or use standard Docker networking with port forwarding, or switch to something more sophisticated like Kubernetes and all of the bells and whilstles it can have.

## Requirements

Only works on Linux, with:

- Docker
- Netfilter
- JQ
- SystemD

Everything else is likely to be part of your OS anyway, but the script does check.

## Vibe-coded

This is my first project that majority uses AI-generated code, rather than simply using the AI mode of a search engine to answer specific coding related questions.

Is it better or worse than what I would have hand coded? The answer is probably yes to both. Besides, you should trust my hand-written code the same as you would trust AI-written code...

## Installation

An install script is provided that creates a systemd unit. Run `sudo ./install.sh` to install and start DNFO, once you're happy that the scripts are all safe.

To uninstall, there's `uninstall.sh`.

You can run `dnfo.sh` as root or via `sudo` by hand without installing it if you just want to experiment with it.

## Usage

For any container to use DNFO, it must have appropriate labels attached to it. In a `docker-compose.yml` file, a minimal-ish example would look like this:

```yaml
services:
  web:
    image: nginx:stable
    volumes:
     - ./templates:/etc/nginx/templates
     - ./certs:/etc/nginx/certs
     - ./nginx.conf:/etc/nginx/nginx.conf:ro
    # Nginx is exposed via a MacVLAN network so port forwarding is unused
    #ports:
    #  - "${HOST_IP}:80:80"
    #  - "${HOST_IP}:443:443/tcp"
    #  - "${HOST_IP}:443:443/udp"
    networks:
      extnet:
        ipv4_address: "192.168.123.124"
      # Maybe we still have internal networking (proxying, etc)
      intnet:
    restart: unless-stopped
    labels:
      dnfo.enable: true
      dnfo.input.include: extnet
      dnfo.input.rules: |
        tcp dport {80, 443} accept
        udp dport 443 accept

networks:
  intnet:
  extnet:
    name: extnet
    external: true
```

The next time the container is recreated and the labels applied (i.e. `docker compose up ...`) the container event will be detected by DNFO and rules updated atomically. That should mean network changes are instantaneous. It also peridically reconciles the configuration in case it misses anything, and DNFO also reapplies detected configurations if the DNFO service restarts.

## Labels

| Label                  | Default               | Values / Type                           | Description                                                                                                                                                                         |
|------------------------|-----------------------|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `dnfo.enable`          | `false`               | `boolean`                               | Whether any DNFO rules will be applied to this service container.                                                                                                                   |
| `dnfo.defaults`        | `true`                | `boolean`                               | Sensible default rules will be used such as allowing state-tracked replies etc (see source code for more).                                                                          |
| `dnfo.input.default`   | `drop`                | `drop\|accept`                          | What will the input filter's default action be?                                                                                                                                     |
| `dnfo.forward.default` | `drop`                | `drop\|accept`                          | What will the forwarding filter's default action be?                                                                                                                                |
| `dnfo.output.default`  | `accept`              | `drop\|accept`                          | What will the output filter's default action be?                                                                                                                                    |
| `dnfo.input.ignore`    |                       | Comma-separated list of network names   | DNFO will add an input `accept` rule for any interfaces belonging to networks specified here. Network names are docker network names, not docker compose (TODO).                    |
| `dnfo.input.include`   |                       | Comma-separated list of network names   | DNFO will add `accept` input rules for all interfaces not part of the networks listed here. If a network is listed in both `ignore` and `include`, then `include` takes precedence. |
| `dnfo.input.rules`     |                       | Multi-line list of netfilter rules      | These netfilter rules will be applied to the input filter after the defaults and interface exceptions.                                                                              |
| `dnfo.output.rules`    |                       | Multi-line list of netfilter rules      | As above, but for the output filter                                                                                                                                                 |
| `dnfo.forward.rules`   |                       | Multi-line list of netfilter rules      | As above, but for the forward filter                                                                                                                                                |
| `dnfo.custom.chains`   |                       | Multi-line list of netfilter chains     | Write your input, output and forward chains yourself entirely, overriding defaults and the individual labels above.                                                                 |
| `dnfo.table.name`      | `dnfo_firewall_table` | String, valid netfilter table name      | The table name to use for the chains. This avoids conflicting with any tables used by the Docker daemon (such as `docker-dns`). You are unlikely to want to change this.            |
| `dnfo.custom.nftables` |                       | Multi-line netfilter configuration file | Write the full netfilter config file that will be loaded yourself. You must handle table clearing on refresh, etc.                                                                  |

## Bugs?

Open an issue or PR and I'll take a look.

## Warranty

Nope. Use at your own risk.
