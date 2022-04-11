<img src="http://zenoh.io/img/zenoh-dragon-small.png" width="150">

[![CI](https://github.com/eclipse-zenoh/zenoh-plugin-webserver/workflows/CI/badge.svg)](https://github.com/eclipse-zenoh/zenoh-plugin-webserver/actions?query=workflow%3A%22CI%22)
[![Discord](https://img.shields.io/badge/chat-on%20discord-blue)](https://discord.gg/vSDSpqnbkm)
[![License](https://img.shields.io/badge/License-EPL%202.0-blue)](https://choosealicense.com/licenses/epl-2.0/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Web Server plugin for Eclipse zenoh

The Web Server plugin implements an HTTP server mapping URLs to zenoh keys.  
This plugin can be used to set-up a Web server where the resources are retrieved from geo-distributed
zenoh storages, each leveraging various backends (file system, database, memory...).

**Library name** `zplugin_webserver`

:point_right: **Download stable versions:** https://download.eclipse.org/zenoh/zenoh-plugin-webserver/

:point_right: **Build "master" branch:** see [below](#How-to-build-it)

-------------------------------
## :warning: Documentation for previous 0.5 versions:
The following documentation related to the version currently in development in "master" branch: 0.6.x.

For previous versions see the README and code of the corresponding tagged version:
 - [0.5.0-beta.9](https://github.com/eclipse-zenoh/zenoh-plugin-webserver/tree/0.5.0-beta.9#readme)
 - [0.5.0-beta.8](https://github.com/eclipse-zenoh/zenoh-plugin-webserver/tree/0.5.0-beta.8#readme)

-------------------------------
## **Examples of usage**

Assuming you have a static website, you can:
 - expose the files as zenoh key/values using the [File System backend](https://github.com/eclipse-zenoh/zenoh-backend-filesystem)
 - set-up this Web Server plugin that will allow HTTP clients to browse the files.

Here are the steps:
 1. Make sure the libraries for the File System backend and the Web Server plugin are available for the zenoh router:  
    either installing their packages (depending your platform), either downloading the library files corresponding
    to your platform in your `~/.zenoh/lib` directory.
 2. Copy the website files into a `~/.zenoh/zbackend_fs/my-site` directory (or make it a symbolic link to the path of your website)
 3. Create a `zenoh.json5` configuration file containing:
    ```json5
    {
      plugins: {
        webserver: {
          http_port: "8080"
        },
        storages: {
          backends: {
            fs: {
              storages: {
                demo: {
                  key_expr: "/my-site/**",
                  strip_prefix: "/my-site",
                  dir: "my-site",
                  read_only: true
    } } } } } } }
    ```
 4. Start the zenoh router (`zenohd`). It will automatically load the Web Server plugin and make it available on port 8080. It will also create a storage replying to any zenoh query on key expressions starting with `/my-site/`.  
 Now you can browse your site on http://localhost:8080/my-site.


For more advanced use cases you can also:
 - Have the files of your web sites stored on different hosts. Running a zenoh router with a File System Storage on
   each host allow to make all the files available under the `/my-site` zenoh key.
 - Duplicate the files of your web sites on several hosts to provide fault tolerance.
 - Start several zenoh routers with the Web Service plugin on different hosts (not necessarly the same than the
   hosts running the File System storages). Each host will serve your web site.
 - Use other backends than the File System to store your resources and make them available through zenoh.
   (List of available backends [here](http://zenoh.io/docs/manual/backends-list/)).
 - Deploy a zenoh application that will implement `eval` function for a resource, replying to requests with a
   dynamic content (see the `z_eval` example in
   [Rust](https://github.com/eclipse-zenoh/zenoh/blob/master/zenoh/examples/zenoh/z_eval.rs) or
   [Python](https://github.com/eclipse-zenoh/zenoh-python/blob/master/examples/zenoh/z_eval.py)).

-------------------------------
## **Configuration**

In its configuration part, the plugin supports those settings:
 - **`http_port`** - int or string - required:  
   either a port number as an integer or a string, either a string with format `"<local_ip>:<port_number>"`

-------------------------------
## **Troubleshooting**

### *Address already in use*
If in `zenohd` logs you see such error log at startup:
```
[2021-04-12T14:20:51Z ERROR zplugin_webserver] Unable to start http server for REST : Os { code: 48, kind: AddrInUse, message: "Address already in use" }
```
It means another process is already using this port number that the webserver plugin would like to use.
In such case, you have 2 solutions:
 - stop the other process using this port
 - make the webserver plugin to another port changing its `listener` option.

### *Permission denied*
If in `zenohd` logs you see such error log at startup:
```
[2021-04-12T13:55:10Z ERROR zplugin_webserver] Unable to start http server for REST : Os { code: 13, kind: PermissionDenied, message: "Permission denied" 
```
It probably means your OS (this usually happens on Linux) forbids the usage of the configured port for non-root user (actually it usually restricts all ports between 0 and 1024).
In such case, you have 2 solutions:
 - run zenohd with root privileges (via `sudo`)
 - use another changing he webserver plugin's `listener` option.

-------------------------------
## **How to build it**

At first, install [Cargo and Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html). 

:warning: **WARNING** :warning: : As Rust doesn't have a stable ABI, the backend library should be
built with the exact same Rust version than `zenohd`. Otherwise, incompatibilities in memory mapping
of shared types between `zenohd` and the library can lead to a `"SIGSEV"` crash.

To know the Rust version you're `zenohd` has been built with, use the `--version` option.  
Example:
```bash
$ zenohd --version
The zenoh router v0.5.0-beta.5-134-g81e85d7 built with rustc 1.51.0-nightly (2987785df 2020-12-28)
```
Here, `zenohd` has been built with the rustc version `1.51.0-nightly` built on 2020-12-28.  
A nightly build of rustc is included in the **Rustup** nightly toolchain the day after.
Thus you'll need to install to toolchain **`nightly-2020-12-29`**
Install and use this toolchain with the following command:

```bash
$ rustup default nightly-2020-12-29
```

And then build the backend with:

```bash
$ cargo build --release --all-targets
```
