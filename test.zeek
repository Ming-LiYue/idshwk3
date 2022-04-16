global IPtable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    local oriIP: addr = c$id$orig_h;
    if (name == "USER-AGENT") 
    {
        local agent: string = to_lower(value);
        if (oriIP in IPtable) 
        {
            add (IPtable[oriIP])[agent];
        } 
        else 
        {
            IPtable[oriIP] = set(agent);
        }
    }
}

event zeek_done()
{
    for(oriIP in IPtable)
    {
        if(|IPtable[oriIP]| >= 3)
        {
            print fmt("%s is a proxy",oriIP);
        }
    }
}
