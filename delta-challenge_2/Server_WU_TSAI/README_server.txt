Creators: Chen-Yen WU, Richard Bing-Shiun TSAI

Summary:
We created a server with Django in Python. The main objectif is to steal the victim's bank information.

Implementation:
1. We implemented in Python. We'll explain some important steps and parameters.
2. We defined how the login page works. This allows the server to store user information to a file "log.txt" that we created. (cf. login_page_code.png and Stolen_information.png)
3. We defined the important pathways. (cf. pathway_definition.png)


Launch the server and the hacking program:
1. Launch the server from the terminal at IP address 127.0.0.1:80 localhost.(cf. Launch_server.png)
2. Modify the ALLOWED_HOSTS list to add the websites we want to pretend to be, for example "kiwibank.com". (cf. Allowed_hosts.png) (We googled it afterwards and found out that Kiwibank does exist. It's a bank from New Zealand.)
3. Launch the DNS_hijack program with the target address being 127.0.0.1 (cf. Launch_DNS_hijack.png).

Test from a victim's point of view:
1. Type "kiwibank.com" in a browser. (cf. Kiwibank_page d'acceuil.png)
2. Naively type in your login information. (cf.Type_in_bank_information.png)

Steal the information:
1. The stolen information will be at our disposal. (cf. Stolen_information.png)

Things to improve:
User interface
