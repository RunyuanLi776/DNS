
Compile in Linux system：gcc -o c client.c common.c
	             	           gcc -o s server.c common.c


server:
Local-IP   resolve-file-name   cache-file-name  authoritative-server-file-name   local-server-or-not  recursive-or-not

client:
Server-IP  domain-name  type  domain-name  type......

sudo ./s 127.0.0.2 本地 本地C 本地S 1 1
sudo ./s 127.0.0.3 根 根C 根S 0 0
sudo ./s 127.0.0.4 中国与美国 中国与美国C 中国与美国S 0 0
sudo ./s 127.0.0.5 教育.中国 教育.中国C 教育.中国S 0 0
sudo ./s 127.0.0.6 政府.美国 政府.美国C 政府.美国S 0 0
sudo ./s 127.0.0.7 商业与组织 商业与组织C 商业与组织S 0 0

./c 127.0.0.2 主页.北邮.教育.中国 A 系统升级.微软.商业 A 张某某.互联网工程任务组.组织 A 垂雷.教育.中国 CNAME 北邮.教育.中国 MX 主页.北邮.教育.中国 A 白宫.政府.美国 A