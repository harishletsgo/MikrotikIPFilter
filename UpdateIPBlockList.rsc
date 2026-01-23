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

        :local result [/tool fetch url=$url mode=https check-certificate=yes output=user as-value]
        :local content ($result->"data")
        :set content ("" . $content)
        :if ([:len $content] = 0) do={
            :error "Download failed"
        }
        :log info ("BlockIPs: Downloaded " . [:len $content] . " bytes")
        :log info ("BlockIPs: Content type " . [:typeof $content] . " len=" . [:len $content])
        :do {
            :local lfChar [:chr 10]
            :log info "BlockIPs: Debug chr(10) ok"
        } on-error={
            :log error ("BlockIPs: Debug chr failed error=" . $error)
            :error "debug-chr-failed"
        }
        :do {
            :local lfPos [:find $content [:chr 10]]
            :local lfPosStr $lfPos
            :if ($lfPos = nil) do={ :set lfPosStr "nil" }
            :log info ("BlockIPs: First LF pos=" . $lfPosStr)
        } on-error={
            :log error ("BlockIPs: Debug find failed error=" . $error)
            :error "debug-find-failed"
        }
        :do {
            :log info ("BlockIPs: Sample=" . [:pick $content 0 120])
        } on-error={
            :log error ("BlockIPs: Debug pick failed error=" . $error)
            :error "debug-pick-failed"
        }

        :local lineCount 0
        :local candidateCount 0
        :local LF [:chr 10]
        :local pos [:find $content $LF]
        :while ($pos != nil) do={
            :local line [:pick $content 0 $pos]
            :set content [:pick $content ($pos + 1) [:len $content]]
            :set pos [:find $content $LF]
            :set lineCount ($lineCount + 1)

            # Strip CR if present
            :local crPos [:find $line [:chr 13]]
            :if ($crPos != nil) do={
                :set line [:pick $line 0 $crPos]
            }

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

            # Keep only address characters to drop CR or other trailing junk
            :local allowed "0123456789abcdefABCDEF:./"
            :local idx 0
            :local end [:len $line]
            :while ($idx < $end) do={
                :local ch [:pick $line $idx ($idx + 1)]
                :if ([:find $allowed $ch] = -1) do={
                    :set end $idx
                    :set idx $end
                } else={
                    :set idx ($idx + 1)
                }
            }
            :set line [:pick $line 0 $end]

            :if ([:len $line] > 2) do={
                :set candidateCount ($candidateCount + 1)
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
        :if ([:len $content] > 0) do={
            :local line $content
            :set lineCount ($lineCount + 1)

            :local crPos [:find $line [:chr 13]]
            :if ($crPos != nil) do={
                :set line [:pick $line 0 $crPos]
            }
            :if ([:find $line "#"] != -1) do={
                :set line [:pick $line 0 [:find $line "#"]]
            }
            :if ([:find $line ";"] != -1) do={
                :set line [:pick $line 0 [:find $line ";"]]
            }
            :local sp
            :set sp [:find $line " "]
            :if ($sp != nil) do={
                :set line [:pick $line 0 $sp]
            }
            :local allowed "0123456789abcdefABCDEF:./"
            :local idx 0
            :local end [:len $line]
            :while ($idx < $end) do={
                :local ch [:pick $line $idx ($idx + 1)]
                :if ([:find $allowed $ch] = -1) do={
                    :set end $idx
                    :set idx $end
                } else={
                    :set idx ($idx + 1)
                }
            }
            :set line [:pick $line 0 $end]
            :if ([:len $line] > 2) do={
                :set candidateCount ($candidateCount + 1)
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

        :log info ("BlockIPs: Parsed " . $lineCount . " lines, " . $candidateCount . " candidates")
        :log info ("BlockIPs: Added " . $count . " entries from " . $url)
    } on-error={
        :log error ("BlockIPs: Failed processing " . $url . " error=" . $error)
    }
}

:log info "BlockIPs update complete."
