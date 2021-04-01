global t :table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
	if(c$http?$user_agent)
	{
		local src_ip=c$id$orig_h;
		local user_agent=to_lower(c$http$user_agent);
		if(src_ip in t)
		{
			add (t[src_ip])[user_agent];
		}
		else
		{
			t[src_ip]=set(user_agent);
		}
	}
}
event zeek_done()
{
	for (src_ip in t){
		if(|t[src_ip]|>=3)
			print fmt("%s is a proxy",src_ip);
	}
}
