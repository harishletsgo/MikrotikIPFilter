:local listName "BlockIPs"
:local description "Auto-blocked IPs"
:local timeout 1d

:local urls {
    "https://www.spamhaus.org/drop/drop.txt";
    "https://www.spamhaus.org/drop/edrop.txt";
    "https://lists.blocklist.de/lists/all.txt";
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
}

:log info "BlockIPs: Cleaning old dynamic entries..."
:do { /ip firewall address-list remove [find list=$listName dynamic=yes] } on-error={}
:do { /ipv6 firewall address-list remove [find list=$listName dynamic=yes] } on-error={}

:foreach url in=$urls do={

    :local fileName "blocklist.txt"
    :local count 0

    :log info ("BlockIPs: Fetching " . $url)

    :do {

        /tool fetch url=$url dst-path=$fileName mode=https check-certificate=yes

        :if ([:len [/file find name=$fileName]] = 0) do={
            :error "Download failed"
        }

        :local content
        :set content [/file get $fileName contents]

        # Normalize line endings
        :set content [:replace $content "\r" ""]

        # Replace newlines with a SAFE delimiter
        :set content [:replace $content "\n" "|"]

        :set content ($content . "|")
        :local pos [:find $content "|"]
        :while ($pos != nil) do={
            :local line [:pick $content 0 $pos]
            :set content [:pick $content ($pos + 1) [:len $content]]
            :set pos [:find $content "|"]

            # Strip comments
            :if ([:find $line "#"] != -1) do={
                :set line [:pick $line 0 [:find $line "#"]]
            }
            :if ([:find $line ";"] != -1) do={
                :set line [:pick $line 0 [:find $line ";"]]
            }

            # First token only
            :local sp
            :set sp [:find $line " "]
            :if ($sp != nil) do={
                :set line [:pick $line 0 $sp]
            }

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

        :log info ("BlockIPs: Added " . $count . " entries from " . $url)
        /file remove $fileName

    } on-error={
        :log error ("BlockIPs: Failed processing " . $url)
        :do { /file remove $fileName } on-error={}
    }
}

:log info "BlockIPs update complete."
