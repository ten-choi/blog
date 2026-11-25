---
title: "[ aws ] How to Use scp with EC2"
labels: ["Cloud","aws","scp","EC2","Archive"]
published: true
date: 2023-06-15T18:34:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 176
tistoryUrl: "https://yeolceo.tistory.com/176"
tistoryCategory: "Cloud/aws"
tistoryTags: ["scp","KR","EC2","aws"]
tistoryPostedAt: "2023-06-15 18:34:46"
language: en
bloggerPostId: "6780717336994776998"
---
scp stands for secure copy protocol, a way to do SFTP-style transfers over SSH access  
If you look it up in the AWS docs, they kindly tell you to use scp with the command below   
[AWS docs](https://docs.aws.amazon.com/ko_kr/AWSEC2/latest/UserGuide/AccessingInstancesLinux.html)

```shell
scp -i /path/key-pair-name.pem /path/my-file.txt ec2-user@instance-public-dns-name:path/
```

When I ran that command, I got the error below

```shell
scp: Received message too long 1349281121
scp: Ensure the remote shell produces no output for non-interactive sessions.
```

After some digging, it turns out this error happens when attempting SFTP authentication  
If you test the connection with sftp instead of scp, you hit the same issue  
It seems to happen when OpenSSH's sftp server is unavailable or its path can't be found, or  
when something prints unnecessary output while sftp is setting up the initial session

Check /etc/ssh/sshd\_config on the AWS instance  
The line commented out with # below will probably be there uncommented. Comment it out as shown,  
and use the sftp built into the OpenSSH package as in the code block below

```shell
#Subsystem      sftp    /usr/libexec/openssh/sftp-server

Subsystem sftp internal-sftp
ForceCommand internal-sftp -u 0002
```

Why add ForceCommand?  
In my case, using only Subsystem sftp internal-sftp gave me the same error  
Quite a few people wrote that this alone fixed it for them

I additionally used ForceCommand internal-sftp -u 0002  
It enforces the first line's command more strictly. The option sets the umask permissions

```shell
sudo service sshd restart
```

Restart sshd to apply the settings. After that, scp worked normally  
With this setup, you can only connect over SFTP afterward. So once you've moved your files, you need to revert the settings  
Otherwise, you'll get the error below and won't be able to connect anymore

```typescript
This service allows sftp connections only
```
