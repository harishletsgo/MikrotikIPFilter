:local listName "BlockIPs"
:local description "Auto-blocked IPs"
:local timeout 1d

:local url "https://github.com/harishletsgo/MikrotikIPFilter/releases/latest/download/blocklist.txt"

:log info "BlockIPs: Cleaning old dynamic entries..."
:do { /ip firewall address-list remove [find list=$listName dynamic=yes] } on-error={}
:do { /ipv6 firewall address-list remove [find list=$listName dynamic=yes] } on-error={}

:log info ("BlockIPs: Fetching " . $url)

:do {
    :local result [/tool fetch url=$url mode=https check-certificate=yes output=user as-value]
    :local content ($result->"data")
    :set content ("" . $content)
    :if ([:len $content] = 0) do={
        :error "Download failed"
    }

    :local count 0
    :foreach line in=[:toarray $content] do={
        :if ([:len $line] > 2) do={
            :do {
                :if ([:find $line ":"] != -1) do={
                    /ipv6 firewall address-list add list=$listName address=$line comment=$description timeout=$timeout
                } else={
                    /ip firewall address-list add list=$listName address=$line comment=$description timeout=$timeout
                }
                :set count ($count + 1)
            } on-error={}
        }
    }

    :log info ("BlockIPs: Added " . $count . " entries")
} on-error={
    :log error ("BlockIPs: Failed processing " . $url . " error=" . $error)
}

:log info "BlockIPs update complete."
