:local listName "BlockIPs"

# Raw file URL for the generated RouterOS commands.
:local url "https://raw.githubusercontent.com/harishletsgo/MikrotikIPFilter/main/blocklist.rsc"
:local fileName "blocklist.rsc"

:log info "BlockIPs: Cleaning old entries..."
:do { /ip firewall address-list remove [find list=$listName] } on-error={}
:do { /ipv6 firewall address-list remove [find list=$listName] } on-error={}

:log info ("BlockIPs: Fetching " . $url)

:do {
    /tool fetch url=$url dst-path=$fileName mode=https check-certificate=yes
    :if ([:len [/file find name=$fileName]] = 0) do={
        :error "Download failed"
    }

    :import file-name=$fileName
    /file remove $fileName

    :log info "BlockIPs: Import complete"
} on-error={
    :log error ("BlockIPs: Failed processing " . $url . " error=" . $error)
}

:log info "BlockIPs update complete."
