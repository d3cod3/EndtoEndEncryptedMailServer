
# End-to-end (E2EE) Encrypted Email Server

[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/V7V21B90C)

[<img src="https://api.gitsponsors.com/api/badge/img?id=103747390" height="20">](https://api.gitsponsors.com/api/badge/link?p=i0jBzM7ci4Y/JAL++n8TXl2Eh+7THk0q1AUTFQcP0MgFwbCTD+gfeXLGLeKjwzoK9TnugoO1oh8ju2a4LpSNsnO1cPgmbE3sbDFg53cCMGL4CcuEH/CzZ+7JjEAXqcAb)


Table of Contents
=================

   * [Description](#description)
   * [Sources](#sources)
   * [DNS](#dns)
   * [Encryption](#encription)
      * [ENCRYPT the Mail Store](#encrypt-the-mail-store)
   * [Postfix](#postfix)
      * [SSL / Let's Encrypt](#ssl-lets-encrypt)
   * [Dovecot](#dovecot)
   * [GPGIT](#gpgit)
   * [Anti-Spam](#anti-spam)
      * [SPF](#spf)
      * [Amavis](#amavis)
      * [Postgray](#postgray)
      * [OpenDKIM](#opendkim)
      * [Spamassassin](#spamassassin)
   * [Anonymize headers](#anonymize-headers)
   * [FAIL2BAN](#fail2ban)
   * [IPTABLES](#iptables)
   * [Router Settings](#router-settings)
   * [Testing](#testing)
   * [Conclusions](#conclusions)



# Description

Secure (reasonably) host your own e-mail accounts, as e-mail was originally designed to work!

Let's make ourselves more independent from corporations, from others minding our own business, and most important, re-gain control of our personal communication over the web, in this case specifically over e-mail.

Yes, those electronic mail boxes that others maintain for us, the technical infrastructure that give us this ability to communicate instantly with everyone all over the planet, this last revision of what long ago was smoke messages, or carrier pigeons, through the centuries of postal systems, till the actual technology, where we do have, now, nor knowledge or control about every part of the entire mechanism, but hey, they give it to us for free!!!

So

Corporations and governments read and/or store all our emails, plus, we can't even complain about it anymore (from august 2013), and that doesn't mean necessary "spying" until it eventually became that.

And if you're ok with it, then you don't need this tutorial

But in case you are not, good news, i'm going to explain here how to set up an End-to-end encrypted ([E2EE](https://ssd.eff.org/en/glossary/end-end-encryption)) email server, and hosting it in your personal server at home.
I'm assuming here you know how to configure a reasonably secure server at home, but if you don't, you can check my [Raspbian Secure Server Config Tutorial](https://github.com/d3cod3/raspbian-server) first.

# Sources

This is a list of sources and other articles i've used to learn, prototype and realize what i'll try to explain in detail in this tutorial.

Thanks to all this people for the help and knowledge:

[http://sealedabstract.com/code/nsa-proof-your-e-mail-in-2-hours/](http://sealedabstract.com/code/nsa-proof-your-e-mail-in-2-hours/)

[https://scaron.info/blog/debian-mail-postfix-dovecot.html](https://scaron.info/blog/debian-mail-postfix-dovecot.html)

[https://appbead.com/blog/how-to-setup-mail-server-on-debian-8-jessie-with-postfix-dovecot-1.html](https://appbead.com/blog/how-to-setup-mail-server-on-debian-8-jessie-with-postfix-dovecot-1.html)

[https://appbead.com/blog/how-to-setup-mail-server-on-debian-8-jessie-with-postfix-dovecot-2.html](https://appbead.com/blog/how-to-setup-mail-server-on-debian-8-jessie-with-postfix-dovecot-2.html)

[https://www.digitalocean.com/community/tutorials/how-to-set-up-a-postfix-email-server-with-dovecot-dynamic-maildirs-and-lmtp](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-postfix-email-server-with-dovecot-dynamic-maildirs-and-lmtp)

[https://security.stackexchange.com/questions/81944/perfectly-secure-postfix-mta-smtp-configuration](https://security.stackexchange.com/questions/81944/perfectly-secure-postfix-mta-smtp-configuration)

[https://scaron.info/blog/debian-mail-spf-dkim.html](https://scaron.info/blog/debian-mail-spf-dkim.html)

[https://www.upcloud.com/support/secure-postfix-using-lets-encrypt/](https://www.upcloud.com/support/secure-postfix-using-lets-encrypt/)

[https://gist.github.com/jkullick/bbb36828a1f413abd6b9d6431bafa54b](https://gist.github.com/jkullick/bbb36828a1f413abd6b9d6431bafa54b)

[https://www.void.gr/kargig/blog/2013/11/24/anonymize-headers-in-postfix/](https://www.void.gr/kargig/blog/2013/11/24/anonymize-headers-in-postfix/)

[http://kacangbawang.com/encrypting-stored-email-with-postfix/](http://kacangbawang.com/encrypting-stored-email-with-postfix/)

[https://www.grepular.com/Automatically_Encrypting_all_Incoming_Email](https://www.grepular.com/Automatically_Encrypting_all_Incoming_Email)

[https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-9-4-on-debian-8](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-9-4-on-debian-8)

[https://www.void.gr/kargig/blog/2013/11/24/anonymize-headers-in-postfix/](https://www.void.gr/kargig/blog/2013/11/24/anonymize-headers-in-postfix/)



# DNS

So, we'll start with the DNS records, and obviously we need a domain, we can buy one through some hosting platform, or we can obtain one for free (with some limitations, on the name for example). Take a look at [FreeDNS](https://freedns.afraid.org/) if you want to learn more about free DNS hosting and domain hosting.
So we'll use here an example domain called _supersecure.mydomain.net_, and just to avoid confusion, a possible mail address could be:
_astronaut57@supersecure.mydomain.net_.
We are using here a different subdomain to avoid the disruption of the standard mail service usually packed with standard hosting services, for example _mymail@mydomain.net_, so we will maintain the standard mail service on our domain and add a new super-secure encrypted one on a subdomain.
When we have our domain, we'll just need to configure it to point to our public IP address:

- **DNS A** record, that maps your domain name to the IP address
```bash
supersecure  A   YOUR_IPv4_ADDRESS
```

- **MX** record, which tells to the others mail servers where deliver mails
```bash
supersecure           MX      supersecure.mydomain.net
```

- **TXT/SPF** record, a Sender Policy Framework (SPF) record in order to not be considered a spammer
```bash
default._domainkey.supersecure    TXT     v=DKIM1; h=sha256; p=v=DKIM1;h=sha256;k=rsa;p=YOUR_DKIM_KEY; s=email; t=s
supersecure                       txt     v=DKIM1;h=sha256;k=rsa;p=YOUR_DKIM_KEY
supersecure                       TXT     v=spf1 a mx ip4:YOUR_IPv4_ADDRESS ip6:YOUR_IPv6_ADDRESS ~all
```

- **TXT/SPF** record, DMARC record in order to not be considered a spammer by big e-mail providers (google, yahoo, etc...)
```bash
supersecure           TXT     v=DMARC1; p=none
_dmarc.supersecure    TXT     v=DMARC1; p=none
```

Regarding the **YOUR_DKIM_KEY** field, we'll work on that later, when configuring [OpenDKIM](#opendkim) (Domain Keys Identified Mail sender authentication system), so you can wait for that, or jump to the section and close the DNS records config right now, your choice!

That's a standard scenario, feel free to customize yours!

Usually DNS propagation takes a while, so it could be useful to set it at the beginning.

One easy step more, edit the file _/etc/mailname_

```bash
sudo nano /etc/mailname
```

and enter your selected mail domain name, in our case _supersecure.mydomain.net_

Let's start talking about encryption!

# ENCRYPTION

Ok, this step is delicate, so i'll start describing what we're trying to achieve here:
first i want an encrypted mail store for my mail server, but most important, i want every mail account associated with a gpg public key to asymmetrically encrypt messages, so only the users, with his/her private gpg key, will be able to decrypt and read their messages, plus, in case of server compromised, the attacker will own only a bunch of gpg encrypted texts!

So, before we start implementing this, a little reminder:

> Even if you're using the best encrypted super secure mail account of the entire universe, when you write to someone that don't, well, your conversation is potentially already compromised. A reasonably secure conversation over the web must be encrypted on both sides.

If you ended up here not randomly, probably you already know that, but just in case, check this tutorial from Free Software Foundation about [email self-defense](https://emailselfdefense.fsf.org/en/)

Perfect, let's analyze in depth how and why we'll implement the required conditions to obtain such server encryption level.

## ENCRYPT the Mail Store

I'll start with the easy one, encrypt the mail store, and for that we'll use [gocryptfs](https://nuetzlich.net/gocryptfs/), a project inspired by [EncFS](https://vgough.github.io/encfs/)

### WHY

Someone could be asking, why encrypt the mail store if we are going to asymmetrically encrypt every single message with users public gpg keys?
Well, is actually a redundancy, but let's consider this, on one side we'll learn how to properly configure generic encrypted filesystem in user-space, and on another side, we can consider it as planting some kind of honeypot for possible attackers; imagine someone taking control of our server, with read/write access to our mail store, he/she will rapidly detect the presence of gocryptfs, that, like every filesystem encryption mechanism, is potentially vulnerable to some kind of advanced attacks, so he/she will probably start to try to exploit the gocryptfs vulnerabilities (if your are interested, take a look at this audit [here](https://defuse.ca/audits/gocryptfs.htm)), and after some time, maybe, with some luck, he/she will decrypt the mail store, finding a bunch of asymmetric gpg encrypted messages!!! Wouldn't you like, just in that moment, to see his/her face?
And to go further, we could plant some other kind of hidden side-channel remote logging system over our encrypted mail store, in order to try to extract information about our potential attacker working on our compromised server, but this is just a little far away from the purposes and skill level of this tutorial, so i'll let this particular point in the hands of the interested enthusiastic contributor that will teach us how to implement this properly (thanks in advance!).

### HOW

As always, let's install it:

```bash
sudo apt-get install gocryptfs
```

Then create our encrypted filesystem and the mount point, basically we'll create two folders (where you prefer):

```bash
mkdir cipher plain
```

Init our encrypted filesystem (our folder for the mailstore):

```bash
gocryptfs -init cipher
```

and mount it:

```bash
gocryptfs cipher plain
```

We can now try a little test, just listing the content of the folder where we created the two folders, _cypher_ and _plain_ (or whatever names you used)

```bash
ls -la
```

And we will obtain

```bash
ls: cannot access plain: Permission denied
```

But if we list it as sudo

```bash
sudo ls -la
```

obviously no problem!

That's all, we now have a password protected encrypted folder for our mail store. If you want to try it, just create some text file inside the plain folder, and you 'll find a new encrypted file inside cipher folder. Any time we want to mount our plain folder, we just use the second command again.

# POSTFIX

Postfix is a Mail Transfer Agent (MTA), that is, software that sends and receives emails to and from other computers on the network using the Simple Mail Transfer Protocol (SMTP). And as a reminder:

* POP/IMAP are used by a client to read messages from an email server
* SMTP is used to exchange emails between computers

So, let's install it:

```bash
sudo apt-get install postfix
```

A command line GUI will pop up, configure it as follow:

* Internet Site
* your mail server domain: _supersecure.mydomain.net_

Postfix configuration file is located at _/etc/postfix/main.cf_, in case you'll need to change more settings

Here follows a basic configuration:

```bash
myhostname = supersecure.mydomain.net
myorigin = /etc/mailname

append_dot_mydomain = no
readme_directory = no
config_directory = /etc/postfix
inet_interfaces = all
inet_protocols = ipv4
mydestination = supersecure.mydomain.net, supersecure.mydomain.net, localhost.localdomain, localhost
relayhost =
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
```
Now, the default for postfix is to use the _mbox_ format (one single file to store all messages) or the _Maildir_ format (each email stored in a individual file), but we are going to take it a step further and use Dovecot instead, so be patient, we are now going to set up our SSL/TLS certificates, and come back here for the Dovecot part in a bit.


## SSL / Let's Encrypt

We are using here the amazing free, automated and open Certificate Authority called [Let's Encrypt](https://letsencrypt.org/), a project by the [Linux Foundation](https://www.linuxfoundation.org/)

As always, install the module:

```bash
sudo apt-get install letsencrypt
```

And run the certificate creation process:

```bash
sudo letsencrypt certonly --standalone -d <supersecure.mydomain.net>
```

Replace here <supersecure.mydomain.net> with your domain name, obviusly! (and without the < > ...)

Then follow the process:

  1.  Use the default vhost filesystem
  2.  Enter your email server domain name: ex. _supersecure.mydomain.net_
  3.  Enter a contact email
  4.  Read and agree to Let's Encrypt Terms of Service (only if you agree)
  5.  Select the _Secure_ option (HTTPS ONLY)

That's it, if everything went ok, you will have your certificates stored under _/etc/letsencrypt/live/<supersecure.mydomain.net>_

Now we need to enable SMTP-AUTH on Postfix, which will allow a client to identify itself through the authentication mechanism SASL. TLS (Transport Layer Security) will be used to encrypt the authentication process, and once authenticated, our server will allow the client to relay mail.

Here follow the config to add to _/etc/postfix/main.cf_

```bash
smtp_use_tls = yes
smtp_tls_CApath = /etc/ssl/certs
smtp_tls_cert_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/fullchain.pem
smtp_tls_key_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/privkey.pem
smtp_tls_security_level = may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

smtpd_use_tls=yes
smtpd_tls_CApath = /etc/ssl/certs
smtpd_tls_cert_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/privkey.pem

smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtpd_sasl_auth_enable = yes
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous

smtpd_tls_eecdh_grade = strong
smtpd_tls_mandatory_ciphers = medium
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_security_level = may

smtpd_banner = $myhostname ESMTP

smtpd_recipient_restrictions = permit_mynetworks, reject_invalid_hostname, reject_non_fqdn_hostname, reject_non_fqdn_sender, reject_rbl_client sbl.spamhaus.org, reject_unknown_sender_domain, reject_unknown_recipient_domain, permit_sasl_authenticated, reject_unauth_destination
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination

tls_medium_cipherlist = AES128+EECDH:AES128+EDH
tls_preempt_cipherlist = yes

policy-spf_time_limit = 3600s
```

Now, one trick more to have an even better security, generate new [_Diffie Hellman Keys_](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)

```bash
openssl gendh -out /etc/postfix/dh_512.pem -2 512
openssl gendh -out /etc/postfix/dh_2048.pem -2 2048
```

And add it to _/etc/postfix/main.cf_

```bash
smtpd_tls_dh1024_param_file = /etc/postfix/dh_2048.pem
smtpd_tls_dh512_param_file = /etc/postfix/dh_512.pem
```

Then we can edit the other Postfix important config file, _/etc/postfix/master.cf_

```bash
sudo nano /etc/postfix/master.cf
```

And make sure you have this:

```bash
smtp      inet  n       -       -       -       -       smtpd

submission       inet    n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth

smtps     inet  n       -       -       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user=email:email argv=/usr/lib/dovecot/deliver -f ${sender} -d ${recipient}
```

We'll come back later at this file, so study it a little bit and get comfortable with it.

Right, so we have our MTA (Mail Transfer Agent) half configured, already secured with Let's Encrypt certificates and a strong encryption settings; but why only half configured, well, for example our MTA didn't know anything, yet, about possible recipients, who are they? and how we want email to be stored?

Setting up a mail server is not an easy task, especially when we are trying to build up a reasonably secure one (and amazingly encrypted :P), so one step at the time, no rush here, the goal is to learn more as possible, because at the time we'll have this tutorial finished and our mail server up and running, it wouldn't be unusual to have to change or add something in order to avoid the possibility of some brand new attack vector.

But i'm changing course, so let's get back to work, next story, [Dovecot](https://www.dovecot.org/), the open source IMAP and POP3 email server written with security primarily in mind.

# DOVECOT

The usual first step, install it:

```bash
sudo apt-get install dovecot-core dovecot-imapd dovecot-lmtpd dovecot-pgsql postgresql postfix-pgsql
```

As you can see, i've decided to install the dovecot PostgreSQL module, and that's because we will use a PostgreSQL database to securely encrypt and store the mail users data.

Someone could be asking right now, why PostgreSQL and not MySQL or MongoDB or whatever, and the answer is: there is not just one answer!
So to get to the point fast, let's use a line from [_The Database Hacker's Handbook_](https://www.wiley.com/en-gb/The+Database+Hacker%27s+Handbook%3A+Defending+Database+Servers-p-9780764578014), _"By default, PostgreSQL is probably the most security-aware database available ..."_.

So here we are, program and modules installed, now the tricky part, the configuration, and i think now it's time, like Agent Cooper use to say, for a damn fine cup of coffee!

We'll start with the _/etc/dovecot/dovecot.conf_ file

```bash
sudo nano /etc/dovecot/dovecot.conf
```

And set this:

```bash
# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol

listen = *

disable_plaintext_auth = yes
mail_privileged_group = mail

passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
protocols = imap lmtp

namespace inbox {
  inbox = yes

  mailbox Trash {
    auto = subscribe # autocreate and autosubscribe the Trash mailbox
    special_use = \Trash
  }
  mailbox Sent {
    auto = subscribe # autocreate and autosubscribe the Sent mailbox
    special_use = \Sent
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}

service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
      group = postfix
      mode = 0600
      user = postfix
    }
}
protocol lmtp {
    postmaster_address=postmaster@<supersecure.mydomain.net>
    hostname=<supersecure.mydomain.net>
}

ssl = required
ssl_cert = </etc/letsencrypt/live/<supersecure.mydomain.net>/fullchain.pem
ssl_cipher_list = AES128+EECDH:AES128+EDH
ssl_dh_parameters_length = 4096
ssl_key = </etc/letsencrypt/live/<supersecure.mydomain.net>/privkey.pem
ssl_prefer_server_ciphers = yes
ssl_protocols = !SSLv3

userdb {
  driver = prefetch
}

userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf
}

```

So we have connected Dovecot with Postfix, configured a standard inbox for mails, configured the SSL/TLS certificates and instructed Dovecot to search for user data in a SQL database with access specified in _/etc/dovecot/dovecot-sql.conf_ file, so let's edit that one:

```bash
sudo nano /etc/dovecot/dovecot-sql.conf
```

And we edit it as follows:

```bash
driver = pgsql
userdb_warning_disable = yes
connect = host=/var/run/postgresql/ dbname=<your_db_name> user=<your_db_user>
default_pass_scheme = SHA512
password_query = SELECT email as user, password FROM users WHERE email = '%u'
user_query = SELECT email as user, 'maildir:/your_mailstore_path/plain/maildir/'||maildir as mail, '/your_mailstore_path/plain/home/'||maildir as home, 500 as uid, 500 as gid FROM users WHERE email = '%u'
```

We'll leave _dbname_ and _user_ alone just for now, because we haven't created our database to store users data yet, so let's do it, and we'll come back here later.

The idea here is to have the less identifiable information stored in plain on our server, so we will design the simplest of user table structure in our database, with the following fields:

```bash
  Column  |           Type           |   Modifiers   
----------+--------------------------+---------------
 email    | text                     | not null
 pgpkey   | text                     | not null
 password | text                     | not null
 maildir  | text                     | not null
 created  | timestamp with time zone | default now()
```

Where _pgpkey_ field will store the public key related with the email in order to automatically encrypt every receiving message, each user with his public key. The other fields are the common ones, the complete email, the SHA512 hashed password, the timestamp of the mail creation and the name of the directory (_maildir_) in our mailstore were Dovecot will be store (and automatically encrypt thanks to more stuff we'll see later) every user message.

So, first things first, we need now to create the database, and a database user, and that is a really straightforward process, but if you're not familiar with PostgreSQL, let's have a quick recap:

0. Just before we start, let's setup the Postgres Database, first we edit _/etc/postgresql/9.4/main/pg_ident.conf_ file (my version is 9.4, so check yours before for the correct file path)
```bash
sudo nano /etc/postgresql/9.4/main/pg_ident.conf
```

and make it look like this

```bash
# MAPNAME       SYSTEM-USERNAME         PG-USERNAME

mailmap		       dovecot			          testuser
mailmap		       postfix			          testuser
mailmap		       root			              testuser
```

Where _testuser_ will be the name of the postgres user we will use for accessing the mailstore database

then edit _/etc/postgresql/9.4/main/pg_hba.conf_ file

```bash
sudo nano /etc/postgresql/9.4/main/pg_hba.conf
```

and add this line (Warning: Make sure to add it right after the **Put your actual configuration here** comment block! Otherwise one of the default entries might catch first and the database authentication will fail)

```bash
local       mail    all     peer map=mailmap
```

save it and reload postgresql service

```bash
sudo service postgresql reload
```

1.  On Debian, PostgreSQL is installed with a default user and default database both called _postgres_, so

2.  we'll connect to the PostgreSQL console with this default user and
```bash
psql -U postgres -h localhost
```

3.  create our database for the mailstore,
```bash
CREATE DATABASE mailstore_db;
```

4.  create a db user to access this new database (choose your preferred username and password) and
```bash
CREATE USER testuser WITH PASSWORD 'test_password';
```

5.  grant all the necessary privileges to this new db user.
```bash
GRANT ALL PRIVILEGES ON DATABASE "mailstore_db" to testuser;
```

6.  Now exit the PostgreSQL console
```bash
\q
```

7.  And re-log into the PostgreSQL console as the new created _testuser_, to edit our new created db _mailstore_db_
```bash
psql -U testuser -d mailstore_db -h localhost
```

8. And finally, we create our tables, the one for the users, and another one for aliases
```bash
CREATE TABLE users (
  email text NOT NULL,
  pgpkey text NOT NULL,
  password text NOT NULL,
  maildir text NOT NULL,
  created TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE aliases (
  alias text NOT NULL,
  email text NOT NULL
);
```

9.  now we check that everything is in it's right place, we list the databases
```bash
\l
```

my output:

```bash
List of databases
      Name      |   Owner    | Encoding |   Collate   |    Ctype    |   Access privileges   
----------------+------------+----------+-------------+-------------+-----------------------
 mailstore_db   | testuser   | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres       | postgres   | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
```

10. we list the _mailstore_db_ tables
```bash
\dt
```

```bash
List of relations
Schema |  Name   | Type  |   Owner    
-------+---------+-------+------------
public | aliases | table | testuser
public | users   | table | testuser
```

11. and the tables structure
```bash
\d users
```

```bash
  Column  |           Type           |   Modifiers   
----------+--------------------------+---------------
 email    | text                     | not null
 pgpkey   | text                     | not null
 password | text                     | not null
 maildir  | text                     | not null
 created  | timestamp with time zone | default now()
```

```bash
\d aliases
```

```bash
 Column | Type | Modifiers
--------+------+-----------
 alias  | text | not null
 email  | text | not null
```

12. And here we are! We have now our database ready, we can come back to the _/etc/dovecot/dovecot-sql.conf_ file, and finally configure the db name and db username:

```bash
sudo nano /etc/dovecot/dovecot-sql.conf
```

and we edit the specific line:

```bash
connect = host=/var/run/postgresql/ dbname=mailstore_db user=testuser
```

Right after that, we can now tell postfix to deliver mail directly to dovecot, so we open again _/etc/postfix/main.cf_ and added

```bash
mailbox_transport = lmtp:unix:private/dovecot-lmtp
alias_maps = hash:/etc/aliases proxy:pgsql:/etc/postfix/pgsql-aliases.cf
local_recipient_maps = proxy:pgsql:/etc/postfix/pgsql-boxes.cf $alias_maps
```

then we need to create two files, first _/etc/postfix/pgsql-aliases.cf_

```bash
user=testuser
dbname=mailstore_db
table=aliases
select_field=alias
where_field=email
hosts=unix:/var/run/postgresql
```

and then _/etc/postfix/pgsql-boxes.cf_

```bash
user=testuser
dbname=mailstore_db
table=users
select_field=email
where_field=email
hosts=unix:/var/run/postgresql/
```

This is done!

Now restart Dovecot and Postfix to apply the new settings

```bash
sudo service postfix restart
sudo service dovecot restart
```

Amazing! Now, theoretically, we are already able to send and receive emails using secure authentication , **BUT**, in order to be able to do that, we have to create our first user mail account! And how we do that? Well, we just need to add a correct entry in our _users_ table inside our postgres database.

A little digression about a possible scenario here, we could imagine some sort of form in a webpage, for everyone or maybe just for a few (your choice), to sign up and obtain an email account in our server.

Ok, So i'm _astronaut57_, i use this aka almost everywhere on the internet (is it true?, or is it just for the story? you decide!), and, while surfing the web, i happen to enter into this amazing and little mysterious webpage where i can sign up and obtain a really interesting reasonably secure gpg encrypted email account, and i start to think: why not? So the webpage seem legit, i like the Terms of Use, is free and [everything is in it's right place](https://www.youtube.com/watch?v=bD2j0fH6-UQ), let's have one, i'm thinking _astronaut57@supersecure.mydomain.net_

The form moment then, i see that is a really simple one, really straightforward, it don't ask for my telephone number, or my street address in case i loose my devices and for some reason the mail provider decide to send me, printed in paper, the last 7 GB of received emails, or for the name of my dog, among other tipical questions you have to answer when registering for a free (free?) service. No, this form is neat, it ask me for those simple things:

1.  the email name, _astronaut57@supersecure.mydomain.net_, check
2.  the pgp public key you want to associate with this mail account, i create a pgp keypair in my machine at home (or my laptop) associated with this new email, and paste here the public key, check
3.  the password for the account, _*****************************_, check

And that's it, push register button and a message appear that in, let's say, 1 minute, my new email account will be available, with a link to the mail config guide for thunderbird & enigmail. Yes, no checking your email in a browser, this kind of reasonably secure gpg encrypted email account cannot work with the actual browsers security standards. Sounds pro!

That's it, the user is happy, but let's analyze the server side now, we obtain from the online form all the necessary info to add a new entry in our mailstore database _users_ table, so when the user push the register button, we check all the fields (front-end side) and if all is correct, we call a script to add a new entry in our database. I'm not going to cover here how to do that from the front-end, but i'm going to show how to do it the old fashioned way, from the terminal

First of all, we need to SHA512 the password entered by the user, yes, because we have configured dovecot to work with SHA512 password scheme, but most important because we do not want to know anything about the passwords used by our users, so we hash it:

```bash
doveadm pw -s sha512 -r 100
```

Enter the password twice and we will obtain something like this:

```bash
{SHA512}NieQminDE4Ggcewn98nKl3Jhgq7Smn3dLlQ1MyLPswq7njpt8qwsIP4jQ2MR1nhWTQyNMFkwV19g4tPQSBhNeQ==
```

Let's save that somewhere (a variable maybe?) and continue

We log into the PostgreSQL console

```bash
psql -U testuser -d mailstore_db -h localhost
```

then we add the new entry

```bash
INSERT INTO aliases ( alias,email ) VALUES (
  'astronaut57',
  'astronaut57@supersecure.mydomain.net'
);
```

and

```bash
INSERT INTO users ( email,pgpkey,password,maildir ) VALUES (
'astronaut57@supersecure.mydomain.net',
'
-----BEGIN PGP PUBLIC KEY BLOCK-----
................................................................
................................................................
-----END PGP PUBLIC KEY BLOCK-----
',
'{SHA512}NieQminDE4Ggcewn98nKl3Jhgq7Smn3dLlQ1MyLPswq7njpt8qwsIP4jQ2MR1nhWTQyNMFkwV19g4tPQSBhNeQ==',
'astronaut57/'
);
```

And exit PostgreSQL console.
```bash
\q
```

Done, user created and added to the database.

It's time to test the system, sending an email to and from _astronaut57@supersecure.mydomain.net_, and to properly do that, we'll need to configure our thunderbird client imagining we are the real _astronaut57_.

So Thunderbird, new account, with this settings:

1.  Your name:          <THE_USER_NAME_OR_WHATEVER>
2.  Email address:      astronaut57@supersecure.mydomain.net
3.  Password:           <THE_USER_PASSWORD>
4.  Incoming:           IMAP    |    supersecure.mydomain.net    |    993   |   SSL/TLS   |  Normal password
5.  Outgoing:           SMTP    |    supersecure.mydomain.net    |    587   |   STARTTLS  |  Normal password
6.  Username:           astronaut57@supersecure.mydomain.net     |    astronaut57@supersecure.mydomain.net

DONE!

If everything went ok, all the config files are correct and the DNS of your server are working, then you will be able now to send and receive emails from/to your new email address _astronaut57@supersecure.mydomain.net_

But where is the encryption? Well, we have some more work to do, so next story, [GPGIT](https://gitlab.com/mikecardwell/gpgit)!

# GPGIT

I want to remember something here, maybe i'm repeating but i believe it's important to make it clear, WE ARE NOT building a NSA-proof mail server, the skill level and the infrastructure to try that is far beyond the knowledge available in this tutorial, but, we can say without doubts that our system, if working properly, will maintain at least confidentiality and authenticity of our email service; and if some evil hacker attack us with some 0-day, gaining temporary control over the server, this scheme with automated encryption we are building will keep the contents of all our users mails secret.

So, how we do it?

This is the idea, we'll set up a trigger on every message arriving (at Postfix level) to the server that will call an encryption function, as we have every account related with a pgp public key (nothing dangerous to store public keys on the server), we'll use this key to encrypt the messages, so the message will land automatically encrypted. Only the owner of the account, or the one who control the associated private key, will be able to open and read the content of the messages (remember that this mechanism make impossible to send messages with multiple recipients, so one message at the time).

And how we treat the message sending or the _sent_ folder? Well, we are focusing on security and privacy here, so this mail server will not have the _sent_ folder, for the following reasons:

1.  An obvious and easy one is that we don't know if the recipients, on the other side, use encryption or not, so even if on our side the sent message is safe, on the other side could be stored in plain, so we just lost confidentiality.

2.  Postfix do not differentiate incoming mail from outgoing mail, so everything must be handled in the same hook. Due to that apply the trigger to outgoing email will need saving the _stdin_ content to the filesystem temporarily, and this is vulnerable to forensic recover. This could be partially resolved with encrypted folder/volumes, but there is a bigger problem:

3.  If we want to make changes to the _IMAP_ mailbox, we'll need that mailbox username/password, and there is no way of doing that without store this credentials somewhere on plaintext (remember, we store in our mail user database the email in plain, but we hash with SHA512 the user password). Or else use a "master" account with read/write permission over all the accounts, but this is really counter-productive to what we are trying to do here.

In conclusion, we are not going to have here the typical _sent_ folder with a copy of our sent messages, if we want a copy of something we are sending, we just re-send the message to ourselves. Plus, we can add a filter in Thunderbird, [thunderbird filters](http://write.flossmanuals.net/thunderbird/filters/), to automatically move a message into the _sent_ folder if comes directly from ourselves.

Installation time! We need to install the [Enigmail](https://www.enigmail.net/index.php/en/) plugin on our local machine (and gpg obviously, but if we already created our keypair before, we already have it!), while on the server (if debian) comes preinstalled, so we check the version:

```bash
gpg --version
```

```bash
gpg (GnuPG) 2.1.18
libgcrypt 1.7.6-beta
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Home: /home/user/.gnupg
Supported algorithms:
Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2
```

In case your linux distro doesn't come with gpg preinstalled, just install it.

Next, we need to create an unprivileged user for running the encryption scripts:

```bash
sudo adduser --shell /bin/false --home /var/opt/gpgit --disabled-password --disabled-login --gecos "" gpgit
```

then set up _gpg_ for this user (if you're not familiar with gpg, you can start [here](https://theprivacyguide.org/tutorials/gpg.html)):

```bash
sudo mkdir /var/opt/gpgit/.gnupg
sudo chown gpgit:gpgit /var/opt/gpgit/.gnupg
sudo chmod 700 /var/opt/gpgit/.gnupg
# Import the mail users public keys (we import this one, but this must be repeated for each new registered user)
sudo -u gpgit /usr/bin/gpg --homedir=/var/opt/gpgit/.gnupg --import astronaut57@supersecure.mydomain.net.gpg
# List all imported keys (you should see the just imported key)
sudo -u gpgit /usr/bin/gpg --homedir=/var/opt/gpgit/.gnupg/ --list-keys
# give ultimate trust (5) to the imported key
sudo -u gpgit /usr/bin/gpg --homedir=/var/opt/gpgit/.gnupg --edit-key astronaut57@supersecure.mydomain.net trust quit
```

We then install (clone) gpgit script by Mark Cardwell from [here](https://gitlab.com/mikecardwell/gpgit), inside our newly created _gpgit_ user home folder:

```bash
cd /var/opt/gpgit/
sudo -u gpgit /usr/bin/git clone https://gitlab.com/mikecardwell/gpgit
```

If necessary, install the required Perl modules, we are using here the [cpan](https://www.cpan.org/) console:

```bash
# install cpanminus
cpan App::cpanminus
# Now install module.
cpanm Mail::GnuPG
# or any others you may be missing
# cpanm XXX::YYY
```

And finally a little test:

```bash
# this should produce a text file with some b64 data, call the command, wait two seconds, then Ctrl-D
sudo -u gpgit /var/opt/gpgit/gpgit/gpgit.pl astronaut57@supersecure.mydomain.net > /var/opt/gpgit/success
cat /var/opt/gpgit/success
```

My output:

```bash
Content-Type: multipart/encrypted; boundary="----------=_1524436225-25788-0"; protocol="application/pgp-encrypted"

This is a multi-part message in MIME format...

------------=_1524436225-25788-0
Content-Type: application/pgp-encrypted; name="msg.asc"
Content-Disposition: inline; filename="msg.asc"
Content-Transfer-Encoding: 7bit

Version: 1
------------=_1524436225-25788-0
Content-Type: application/octet-stream
Content-Disposition: inline
Content-Transfer-Encoding: 7bit

-----BEGIN PGP MESSAGE-----

hQIMA6SuSblhzUCkAQ/+M520zEDPEOwmsPmjOS8Sv1teygcLbId5wUEwHgPz3o3r
teu7UIUXHvVLGVW9zg7ggIaUzMj+XPPhZvmKWLyK2pBNYOjwaBAYTjlB6y6ANs3b
M2t3/OUzoFRchdY6AVZQGwD+RNvb0pUTrvf4tC8TQBHbdOYojP2qodNVTJ408kxx
q0qcoYjHz+1L7Qng8uMXSX1LI4PNWcVqG0sBvtiaTUgDDVJb7MA5Ig/EW2V8FB1i
sTAR13sDJ7VhbCasDUUBhs0x1Y0ssj+LiDd1qkQNgqvePqJ0RikwtQ9OzaZ11o5H
N/FikujIYUTzoGvR7KBLmGBpUyAwagkbUlJKsGhLNDaSo32dgnz34UBaTxa41GDF
M3JGuhiIQe7nH9AMavTt4sHc28cmYdqnOOKDA+1dwE6lLOoGQg3IkFlz0cunN8ee
JVyuC7lUnEKgJJVjRaWQOlzWltwIuQXEitoj33/bMktYtEbRydRSwvM2ajmpgEyF
U0lTr/yz/PdfBk/kPrezPIAJFMWDun58Vi+VJemvCsOxgi7e0MwrEpe4u9ap1SKf
g2zEXovVlPFldapqFztSjLKIlskompXQbSs4IaF4ciMXatRUNpzIFICUFMw/Cd4T
G2N9Kq5f4hGdskbb5PVAqWXvy8m7zH3pIrQaPQHJAFbAh99Ull4w4LCaEGUjI9bS
PAGEAqNYGUUuvN+srtVtj/ciMMET2VvPoA0BuiVzbD7XZqdF2jlf6fL8JAQ3zls2
CHUR7ahLHVffgqHqPA==
=h9sJ
-----END PGP MESSAGE-----

------------=_1524436225-25788-0--
```

It's working, **gpgit** Perl script from Mike Cardwell automatically use the email address provided, to look up the public key that the message will be encrypted with.

Almost finished, we just need now to trigger this script on arriving mail in Postfix, and basically this is just a filter over the incoming messages, not so different to the spam filters that we'll implement later, in this case encrypting the content of the message before delivery.

Postfix then, but we need here to clarify something about how we achieve this; the Postfix mechanics doesn't let us apply some content filter to incoming messages only, if we setup some filter, it will be applied to all messages, incoming and outgoing. So far so good, the gpgit script search for local installed gpg public keys, so the only keys available will be the ones related with users accounts, so the only messages encrypted will be the ones with a local mail user as recipients, meaning incoming messages only! We let on the client side the possible encryption of outgoing messages, using the common (and user friendly) mechanism through the enigmail plugin.
And a last detail, while the message will be encrypted, headers (from:, time:, and more metadata) will not, so later we'll add some sort of anonymization of message headers, but let just finish the encryption part first.

We open again the _/etc/postfix/master.cf_ Postfix config file

```bash
sudo nano /etc/postfix/master.cf
```

and add _-o content_filter=gpgit-pipe_ to the specified blocks (smtp, smtps, submission)

```bash
smtp      inet  n       -       -       -       -       smtpd
  -o content_filter=gpgit-pipe

submission       inet    n       -       n       -       -       smtpd
  -o content_filter=gpgit-pipe

smtps     inet  n       -       -       -       -       smtpd
  -o content_filter=gpgit-pipe
```

and at the end we add our hook

```bash
gpgit-pipe unix -     n       n       -       -       pipe
  flags=Rq user=gpgit argv=/var/opt/gpgit/gpgit_postfix.sh -oi -f ${sender} ${recipient}
```

Save it and close it. Now we need to create the _gpgit_postfix.sh_ script to finally get the job done!

Create the new file

```bash
sudo -u gpgit nano /var/opt/gpgit/gpgit_postfix.sh
```

with the following contents

```bash
#!/bin/bash

SENDMAIL=/usr/sbin/sendmail
GPGIT=/var/opt/gpgit/gpgit/gpgit.pl

#encrypt and resend directly from stdin
set -o pipefail

${GPGIT} "$4" |  ${SENDMAIL} "$@"

exit $?
```

save & close it, and change the file permission to 755

```bash
sudo chmod 755 /var/opt/gpgit/gpgit_postfix.sh
```

At this point, we should have everything tuned, restart Postfix service

```bash
sudo service postfix restart
```

And try to send an email to your brand new email account _astronaut57@supersecure.mydomain.net_, if everything is correct, thunderbird will ask for your private key password to decrypt your incoming message (client side).

The beauty of this piped construct (the script in _/var/opt/gpgit/gpgit_postfix.sh_) is in that the message body is never saved as a file on the mail server disk. If it was, it could potentially be recovered via forensic disk analysis, which is undesirable.

This chapter is not a walk in the park, as they say, so if you want some more technical details, or just more info about that, here you'll find the original article from which i've extracted this part of the tutorial: [Encrypting Stored Email with Postfix](http://kacangbawang.com/encrypting-stored-email-with-postfix/)

Next story, anti-spam chicanery!

# Anti-Spam

Well, yes, email use to go hand by hand with spam, their relationship has grown exponentially over the years, and all the ecosystems around email are filled with various anti-spam hacks and workarounds.
The combination of tools we are going to use here for our mail server is, at the moment of writing (April 2018), pretty solid and well tested, we will try at the end a quality test over our mail server using [MailTester](https://www.mail-tester.com/) spam test, and i've used this combination in my personal mail server for almost a year with 0 spam issues, yes, ZERO!
This coupled with properly configured jails in [Fail2ban](#fail2ban) will give us a solid system protected from spammers.
But first of all, we'll need to not be considered spammers ourselves, we'll start then with SPF!

## SPF

Sender Policy Framework (SPF) is one of the two services you should configure in order not to be considered as a spammer by major e-mail service providers.

So install it:

```bash
sudo apt-get install postfix-policyd-spf-python
```

edit the postfix _/etc/postfix/master.cf_ config file

```bash
sudo nano /etc/postfix/master.cf
```

and add this

```bash
policy-spf  unix  -       n       n       -       -       spawn
     user=nobody argv=/usr/bin/policyd-spf
```

Then, modify this line in _/etc/postfix/main.cf_

```bash
smtpd_recipient_restrictions = permit_mynetworks, reject_invalid_hostname, reject_non_fqdn_hostname, reject_non_fqdn_sender, reject_rbl_client sbl.spamhaus.org, reject_unknown_sender_domain, reject_unknown_recipient_domain, permit_sasl_authenticated, reject_unauth_destination, check_policy_service unix:private/policy-spf
```

as you can see, we added at the end _check_policy_service unix:private/policy-spf_, to activate the SPF policy in Postfix.

And that's it, we already setup a SPF record in our DNS at the beginning of this tutorial, so we are good to go to the next story, Amavis!

## AMAVIS

[Amavis](https://amavis.org/) is a high-performance and reliable interface between mailer (MTA) and one or more content checkers: virus scanners, and/or Mail::SpamAssassin Perl module.

As always

```bash
sudo apt-get install amavisd-new
```

Then the config, first we need to tell Postfix about our content filter

```bash
sudo nano /etc/postfix/main.cf
```

add this

```bash
content_filter = amavis:[127.0.0.1]:10024
```

save it and open _/etc/postfix/master.cf_

```bash
sudo nano /etc/postfix/master.cf
```

and add this blocks

```bash
amavis           unix    -       -       -       -       2       smtp
  -o smtp_send_xforward_command=yes
  -o smtp_tls_security_level=none

127.0.0.1:10025  inet    n       -       -       -       -       smtpd
  -o content_filter=
  -o receive_override_options=no_milters
```

Save it and restart Postfix

```bash
sudo service postfix restart
```

Then the last one, open _/etc/amavis/conf.d/20-debian_defaults_ file

```bash
sudo nano /etc/amavis/conf.d/20-debian_defaults
```

and make this line looks like this

```bash
$inet_socket_bind = '127.0.0.1';
```

That's was easy! So next one, Postgray!

## POSTGRAY

[Postgrey](http://postgrey.schweikert.ch/) is a Postfix policy server implementing greylisting developed by [David Schweikert](http://david.schweikert.ch/).

Install it

```bash
sudo apt-get install postgrey
```

Then edit his config file _/etc/default/postgrey_

```bash
sudo nano /etc/default/postgrey
```

and edit this line as follows

```bash
POSTGREY_OPTS="--inet=10023 --delay=30"
```

Ok, now we need to tell Postfix to use Postgray, edit the usual _/etc/postfix/main.cf_ file and modify this line

```bash
smtpd_recipient_restrictions = permit_mynetworks, reject_invalid_hostname, reject_non_fqdn_hostname, reject_non_fqdn_sender, reject_rbl_client sbl.spamhaus.org, reject_unknown_sender_domain, reject_unknown_recipient_domain, permit_sasl_authenticated, reject_unauth_destination, check_policy_service inet:[127.0.0.1]:10023, check_policy_service unix:private/policy-spf
```

adding _check_policy_service inet:[127.0.0.1]:10023_ just before the SPF policy check

restart Postfix as usual

```bash
sudo service postfix restart
```

and jump to the next one, OpenDKIM!

## OPENDKIM

DomainKeys Identified Mail (DKIM) is the other service you need to configure in order not to be considered as a spammer by big e-mail providers. It ties your e-mail server to your domain name, so that receivers can check that e-mails originating from your domain indeed correspond to your computer. So we'll use [opendkim](http://www.opendkim.org/) for this; as always, install it:

```bash
sudo apt-get install opendkim opendkim-tools
```

DKIM is based on asymmetric cryptography. Basically, we will generate a pair of public/private keys on your server, and publish the public key on your DNS records (remember the beginning of the tutorial?).

So, first we edit _/etc/opendkim.conf_

```bash
sudo nano /etc/opendkim.conf
```

and we make sure it contains what follows

```bash
Syslog                  yes

UMask                   002

AutoRestart             Yes
AutoRestartRate         10/1h
SyslogSuccess           Yes
LogWhy                  Yes

Canonicalization        relaxed/simple

ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256

UserID                  opendkim:opendkim

Socket                  inet:12345@localhost
```

Then we edit _/etc/opendkim/TrustedHosts_ and we make sure it contains all our domains, hostnames or IP addresses

```bash
127.0.0.1
localhost
*.supersecure.mydomain.net
```

next, we tell Postfix to connect with OpenDKIM, we open _/etc/postfix/main.cf_ and add this:

```bash
# DKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:12345
non_smtpd_milters = inet:localhost:12345
```

good, now we need to generate a keypair for our server:

```bash
sudo mkdir /etc/opendkim/keys/<supersecure.mydomain.net>
sudo chown opendkim:opendkim -R /etc/opendkim/keys/<supersecure.mydomain.net>
cd /etc/opendkim/keys/<supersecure.mydomain.net>
sudo opendkim-genkey -s default -d <supersecure.mydomain.net>
sudo chown opendkim:opendkim /etc/opendkim/keys/<supersecure.mydomain.net>/default.private
```

Keypair created, now we add the key to _/etc/opendkim/KeyTable_

```bash
default._domainkey.<supersecure.mydomain.net> <supersecure.mydomain.net>:default:/etc/opendkim/keys/<supersecure.mydomain.net>/default.private
```

and don't forget to change _<supersecure.mydomain.net>_ with your real domain (and cut the < > !!!)

ok, last one, in _/etc/opendkim/SigningTable_ file, we add this:

```bash
*@<supersecure.mydomain.net> default._domainkey.<supersecure.mydomain.net>
```

With everything saved, restart Postfix and opendkim and we have it!

```bash
sudo service postfix restart
sudo service opendkim restart
```

And to finish this chapter, the last thing will be to display our openDKIM DNS generated key, to add it to our **TXT/SPF** record and finally have it properly configured

```bash
sudo cat /etc/opendkim/keys/<supersecure.mydomain.net>/default.txt
```

my output (some)

```bash
default._domainkey	IN	TXT	( "v=DKIM1; h=sha256; k=rsa; "
	  "p=WT...long hash....niuohefopUgIPUGUVWYF" )  ; ----- DKIM key default for <supersecure.mydomain.net>
```

And that's it! Wait some time for the DNS to propagate and test it

```bash
dig <supersecure.mydomain.net> TXT
```

Our mail server is starting to look really fine-tuned! It's time for our last tool of anti-spam magic, next story [SpamAssassin](https://spamassassin.apache.org/)

## SPAMASSASSIN

SpamAssassin is a server level filter to avoid junk mails (spam), it's a renowned one and easy to configure.

Install it

```bash
sudo apt-get install spamassassin spamc
```

and add it to Postfix as _content_filter_, but we have a little problem here, we already have a _content_filter_ configured in Postfix, we add it with the setup of [GPGIT](#gpgit), and we can't add two _content_filter_.

Anyway, every problem have a solution, and this one is pretty easy to solve, we just need to modify our _gpgit_postfix.sh_ script file, in order to filter the message with SpamAssassin BEFORE encrypting it.

So we open the file and make it look like that:

```bash
sudo nano /var/opt/gpgit/gpgit_postfix.sh
```

```bash
#!/bin/bash

SENDMAIL=/usr/sbin/sendmail
SPAMASSASSIN=/usr/bin/spamc
GPGIT=/var/opt/gpgit/gpgit/gpgit.pl

#encrypt and resend directly from stdin
set -o pipefail

${SPAMASSASSIN} | ${GPGIT} "$4" |  ${SENDMAIL} "$@"

exit $?
```

save it and the last step, we open _/etc/spamassassin/local.cf_ file and uncomment this line

```bash
rewrite_header Subject *****SPAM*****
```

to label spam mails.

We have it!

Form time to time, if you want to update the SpamAssassin database, you can run this command

```bash
sa-update
```

and restart SpamAssassin

```bash
/etc/init.d/spamassassin restart
```

We are almost finished, just one step more to increase anonymity on our mail server, next story: Anonymize Headers!

# ANONYMIZE HEADERS

In Postfix, we can manage to hide the sender originating IP (plus some other stuff), in order to reduce the presence of user information on the server, and this can be achieved using Postfix's _cleanup_service_name_ directive; let's do it!

Install _postfix-pcre_ module

```bash
sudo apt-get install postfix-pcre
```

then create a file _/etc/postfix/smtp_header_checks.pcre_ with this content:

```bash
/^\s*(Received: from)[^\n]*(.*)/ REPLACE $1 [127.0.0.1] (localhost [127.0.0.1])$2
/^\s*User-Agent/        IGNORE
/^\s*X-Enigmail/        IGNORE
/^\s*X-Mailer/          IGNORE
/^\s*X-Originating-IP/  IGNORE
```

save&close

Now we edit again the _/etc/postfix/master.cf_ Postfix config file, and add this:

```bash
-o cleanup_service_name=subcleanup
```

at the end of _smtp_, _submission_, _smtps_ and _amavis_ blocks, just like this:

```bash
smtp      inet  n       -       -       -       -       smtpd
  ........
  -o cleanup_service_name=subcleanup

submission       inet    n       -       n       -       -       smtpd
  ........
  -o cleanup_service_name=subcleanup

smtps     inet  n       -       -       -       -       smtpd
  ........
  -o cleanup_service_name=subcleanup

amavis           unix    -       -       -       -       2       smtp
  ........
  -o cleanup_service_name=subcleanup
```

then at the end of the config file we add

```bash
subcleanup unix n       -       -       -       0       cleanup
    -o header_checks=pcre:/etc/postfix/smtp_header_checks.pcre
```

and that's it! We now restart Postfix as always, and if everything is correct, our mail server is perfectly up&running!

We are going to add some security on the next story, using our favorite intrusion prevention software, [Fail2Ban](https://www.fail2ban.org/wiki/index.php/Main_Page)

# FAIL2BAN

If you like stuff as set up your own server at home, or this is your field of work, you must probably know really well Fail2Ban software, but if you're not, well, it's time you catch up the good stuff, because intrusion detection systems, nowadays, are more than necessaries.

More of the same, install it

```bash
sudo apt-get install fail2ban
```

make a local copy of the configuration file

```bash
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

and edit your local copy

```bash
nano /etc/fail2ban/jail.local
```

then go down to the _[JAILS]_ section and search for _# Mail servers_ line.

Ok, we need now to activate jails for Postfix, Dovecot y SASL:

```bash
[postfix]

enabled  = true
port     = smtp,ssmtp,submission
filter   = postfix
logpath  = /var/log/mail.log


[sasl]

enabled  = true
port     = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter   = postfix-sasl
# You might consider monitoring /var/log/mail.warn instead if you are
# running postfix since it would provide the same log lines at the
# "warn" level but overall at the smaller filesize.
logpath  = /var/log/mail.warn
maxretry = 1
bantime  = 21600

[dovecot]

enabled = true
port    = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter  = dovecot
logpath = /var/log/mail.log
```

Perfect, this is the end of the road, close the config fail and restart fail2ban

```bash
sudo /etc/init.d/fail2ban restart
```

Now that our server is running as we want it, properly configured and protected, we can now open the necessary ports on our firewall and on our router, to finally make our mail server visible to the Internet.

Next short stories, _iptables_ and _router settings_

# IPTABLES

Just add this rules to your firewall, adjust them if your not using _iptables_

```bash
sudo iptables -A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 587 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 993 -j ACCEPT

sudo iptables -A OUTPUT -p tcp -m tcp --dport 25 -m state --state NEW -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 587 -m state --state NEW -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --sport 587 -m state --state ESTABLISHED -j ACCEPT
```

# ROUTER SETTINGS

open router port 25 (SMTP, to instantiate servers communication), 587 (SUBMISSION, secure send), and 993 (IMAPS over TLS/SSL, secure receive)


# Testing

This is the end of another journey, we can enjoy it, ask ourselves if was worth the hours of work, and if we learned something, important or not, learning can only make us better.

But before let's try a test, a comprehensive one about the spammyness of our mail server, plus a lot of info on how to improve the quality of the service, is [mail tester](https://www.mail-tester.com/), i'll let you try yours then, and here you have the result for my mail server, the one identically configured as the tutorial itself

![End-to-end (E2EE) Encrypted Email Server](https://github.com/d3cod3/EndtoEndEncryptedMailServer/blob/master/img/mail_score.jpg)

and just for having something to compare, this is another test from a gmail account (you can try with one if you have it, and you will see the same result)

![Gmail](https://github.com/d3cod3/EndtoEndEncryptedMailServer/blob/master/img/gmail_score.jpg)


# Conclusions

...soon
