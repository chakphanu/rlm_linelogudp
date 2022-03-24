# rlm_linelogudp
freeradius linelog to UDP


## example send packet counter to influxdb
### mods-enabled/linelogudp
```
linelogudp {
    reference = "Accounting-Request.%{%{Acct-Status-Type}:-unknown}"

}


linelogudp influxdb {
    reference = "Accounting-Request.%{%{Acct-Status-Type}:-unknown}"
    Accounting-Request {
                Interim-Update = "radius,username=%{User-Name} acctsessiontime=%{Acct-Session-Time},acctinputoctets=%{Acct-Input-Octets64},acctoutputoctets=%{Acct-Output-Octets64}"

    }
}
```


### add influxdb to accounting {} section
```
#
#  Accounting.  Log the accounting data.
#
accounting {

 # For Exec-Program and Exec-Program-Wait
 exec
 
 # linelogudp
 influxdb


}

```
