<link rel="stylesheet" type="text/css" href="style.css">

# newsgears-broker

newsgears is a multi-user, self-hosted all-in-one RSS reader/aggregator platform.

This repository contains the Broker server. The broker is responsible for facilitating real-time updates between 
the NewsGears RSS client and server components.

## 1. Quick-start using pre-built containers:

If you don't want to do development, just start NewsGears using pre-built containers:

```
docker ...
```

<hr>

## 3. For local development:

If you don't want to use the pre-built containers (i.e., you want to make custom code changes and build your own containers), then use the following instructions.

### Setup command aliases:

A script called `build_module.sh` is provided to expedite image assembly.  Setup command aliases to run it to build the required images after you make code changes:

```
alias ng-broker='./build_module.sh newsgears-broker'
```

#### Alternately, setup aliases build debuggable containers:

```
alias ng-broker='./build_module.sh newsgears-api --debug 55005'
```

*Debuggable containers pause on startup until a remote debugger is attached on the specified port.*

### Build and run:

#### Run the following command in the directory that contains ```newsgears-broker```:

```
ng-broker && docker ...
```

Boot down in the regular way, by using ```docker ...``` in the ```newsgears-broker``` directory.

<hr> 

You can also use the `ng-broker` alias to rebuild the container (i.e., to deploy code changes).

```
$ ng-broker # rebuild the broker server container 
```
