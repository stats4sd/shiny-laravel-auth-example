# Readme
This guide shows one way that a Laravel app can communicate with a Shiny app, e.g. to enable only users authenticated within Laravel to view the Shiny app. The goal is to allow a Shiny application to be embedded in an iframe on a Laravel page. Users should be able to view the Shiny application **only** under the following conditions:
1. The user is authenticated in Laravel, and able to access the specific page.
	- Any form of Laravel authorisation can be used here to ensure only the correct users have access to the page.
2. The user is viewing the Shiny application within the Laravel page, and **not** by visiting the Shiny app's url directly.

The shiny app must be setup so that by default nothing deemed 'private' should be shown until the application receives a validated POST request to confirm the user is authorised.  Every unique session in Shiny must be authenticated by the external application before any secure sections can be made visible in Shiny.

# Summary of the Authentication Flow
Given Shiny and Laravel are entirely separate applications, the process to enable secure communication between them is a bit convoluted. The summary of the process is as follows:

1. The user logs into the Laravel site and visits the page.
2. When the page loads, the iframe loads the Shiny application.
3. Within Shiny:
	1. The Shiny UI includes Javascript that sends a message to the window's parent, telling the parent the unique session ID.
	2. The Shiny Server uses `server$registerDataObj()` to setup a unique, secret url to listen for external http requests. This unique URL is written to a file in a secure location on the server. The filename is the session ID that was passed to the window.parent.
4. Within Laravel:
	1. The page containing the iframe includes JavaScript that listens for messages from the configured Shiny url. Upon receipt, a POST reequest is sent to the Laravel server.
	2. The Laravel Application confirms the current user is authorised to view the Shiny application, then locates the file contaiing the secure URL and sends a POST request back to the Shiny application.
5. Within Shiny:
	1. When Shiny receives the valid POST request from Laravel, the main content is unlocked for that session.

> The following process is built and tested for the following setup:
> - Ubuntu 20.04
> - A Laravel application deployed via [Laravel Forge](https://forge.laravel.com/)
> If you use a different setup (e.g. different Linux distro, or a different tool to deploy your Laravel application), the method should still work, but you should adapt the specific instructions to suit your server environment.


# Setup
The setup describes the following process:

1. Install Shiny
2. Setup Nginx to serve Shiny on a different domain / subdomain (including SSL setup)
3. Shiny app setup
4. Laravel app setup

If you already have Shiny server installed and working on the same server as your Laravel application, skip to step 3:


## 1. Install Shiny
The first step is to install R + Shiny onto the same server that runs your Laravel Application.

The below script was updated in March 2022. Check if a newer version of R Shiny Server is available [here](https://www.rstudio.com/products/shiny/download-server/ubuntu/).

On the server, run:

```bash
# Install R
sudo apt-get install r-base

# Install the shiny R package
sudo su - \
-c "R -e \"install.packages('shiny', repos='https://cran.rstudio.com/')\""

# Install gdebi + the Shiny Server
sudo apt-get install gdebi-core
wget https://download3.rstudio.org/ubuntu-14.04/x86_64/shiny-server-1.5.17.973-amd64.deb
sudo gdebi shiny-server-1.5.17.973-amd64.deb

```

Shiny should now be installed and running on the server. The configuration file is at: `/etc/shiny-server/shiny-server.conf`. We suggest making the following modifications:

- `run_as forge;` - This makes it easier when working via SSH, as you can log in as the forge user and have access to both Laravel and Shiny applications.
- `site_dir /home/forge/shiny;` - Change the site directory to be within the forge user home folder. This lets you keep your Shiny application(s) next to your Laravel application(s), and makes it easier when setting up the link.

>There will be schools of thought that say you should have a different user account for each application running on a server, to avoid potential security issues and ensure 1 app does not have full access to the other. For our purposes, the benefits of running both apps on 1 account outweigh the security implications, but this is something you must decide on a case-by-case basis.
>This process works fine with Shiny running on a different user account, but you will need to modify the location of the shiny app and ensure the folder permissions are correctly setup to allow both Shiny and Laravel to access the appropriate files.

## Nginx Setup

1. The Shiny app requires its own subdomain, separate to the Laravel app. So if your Laravel app is deployed at `example.com`, you should setup a new subdomain: `shiny.example.com`., and point this subdomain the the same server IP.
2. SSH into the server, and create a new nginx config file for the new subdomain:
	1.  `nano /etc/nginx/sites-available/shiny.example.com`
	2. Paste in the following:
```nginx

map $http_upgrade $connection_upgrade {
  default upgrade;
  ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name shiny.example.com;

    location /.well-known/acme-challenge {
		auth_basic off;
		allow all;
		alias /home/forge/.letsencrypt;
    }

    location / {
        proxy_pass http://localhost:3838;
        proxy_redirect / $scheme://$http_host/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 20d;
        proxy_buffering off;
    }

    access_log off;
    error_page 404 /index.php;
}

```


3. Next, generate a new SSL certificate. Do this within Laravel Forge (or via a tool like [Letsencrypt](https://letsencrypt.org/) directly if you do not use Forge):
	- Go to your Laravel site => SSL page.
	- Generate a new certificate with Let's Encrypt.
	- In the "Domains" box, add the new domain - so you then have your 2 domains (1 for Laravel, 1 for Shiny) separated by a coma. For example: `example.com,shiny.example.com`
	- Once you have installed the certificate, activate it in Forge.

4. Finally, we can update the Nginx config to reference the new SSL certificate:
	- SSH into the server, and edit the nginx config file for the new subdomain:
	-  `nano /etc/nginx/sites-available/shiny.example.com`
	- Update the main server block to listen on port 443:
```nginx
    # listen 80; -- delete these lines
    # listen [::]:80; -- delete these lines
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
```

- Find the nginx config created by Laravel Forge, and copy over the SSL and security headers section:
	-  `nano /etc/nginx/sites-available/example.com`
- Copy the entire section from the heading `# FORGE SSL (DO NOT REMOVE!)`, including the following lines:
```
	ssl_certificate
	ssl_certificate_key
	ssl_protocols
	ssl_ciphers
	ssl_prefer_server_ciphers
	ssl_dhparam
	add_header x3
```

- Update the X-Frame-Options line to allow the Shiny domain to be embedded within an iframe on the Laravel application:
	- `add_header X-Frame-Options "ALLOW-FROM shiny.example.com";`
	- The final nginx config should look like the following file: ![[../attachments/shiny-example.com]]

At this point, you should have Shiny installed and working alongside your Laravel application. You can now deploy Shiny applications to your shiny-server root folder (`/home/forge/shiny`, or your own custom path) and have them available at `https://shiny-example.com`.

## 3.  Setup Shiny to be authenticated by external system.


1. We recommend using the dotenv R library to let you store environemt-specific configuration files in a `.env` file:
	- `library(dotenv)`.
	- Add the following variables to a .env file, so they can be referenced in the app:
		- `LARAVEL_APP_URL=https://example.com #The url of the Laravel application`
		- `URL=https://shiny.example.com #The url of this Shiny application`
1. Add the following to the UI section of the app. This will share the current session ID with the parent page, to allow Laravel to find the url linked to this specific session:
```R
tags$head(
	tags$script(
		HTML(
			paste0('Shiny.addCustomMessageHandler("session", function(message) {
					parent.postMessage(message, "', Sys.getenv("LARAVEL_APP_URL"), '")
				});'
			)
		)
	)
)
```

3. Add the following to the server section of the app. This will generate and register a unique URL that the application will listen on, and then write the url to a file on the server:
```R
## Setup POST listener for authentication

auth_url <- session$registerDataObj(
	name = 'testing',
	data = data,
	filter = function(data, req) {
		shiny::httpResponse(
			200, 'text/plain', req$REQUEST_METHOD
		)

	if(req$REQUEST_METHOD == "POST") {

		# TODO: THis is where the app should do whatever it needs to do to reveal the main parts of the app
		updateTextInput(session, 'password', value='arandomvsiaojsheiuvhasodiufhasoeuhauh')

		shiny::httpResponse(
			200, 'text/plain', 'Message received - from Shiny'
		)
	}
  }
)

# extract the specific session ID
session_uuid <- str_replace(auth_url, "session/", "")
session_uuid <- str_replace(session_uuid, "/dataobj/.*", "")

# write the url to a file. The file name is the session ID to enable an external application to target this current session.
# You must ensure this path points to the same location that Laravel will search.
fileConn<-file(paste0("../.sessions/", session_uuid))
writeLines(paste0(Sys.getenv("URL"),"/", auth_url), fileConn)


# send a message to the front-end containing the current session ID.
session$sendCustomMessage('session', session_uuid);

```

## 4. Setup Laravel to authenticate Shiny
Now the Shiny app is setup to send the session ID via a Javascript message, and separaetly share the secure url via a server file, the Laravel app needs to read and respond to these messages.

1. Add the following .env variables:
	1. `SHINY_URL=https://shiny.example.com # The url of the Shiny application`
	2. SHINY_PATH=/home/forge/shiny # The absolute file path of the shiny application on the server
2. Add a new `shiny.php` config file inside the `config` folder to reference this .env variable:
```PHP
<?php

return [
	'url' => env("SHINY_URL", ""),
	'path' => env("SHINY_PATH", ""),
	'app_name' => env("SHINY_APP_NAME", "")
];

```
3. Pick a web page to embed the Shiny app. In the main content, add the following iframe:
```PHP
<iframe id="shiny"
	title="Shiny Dashboard"
	height="1000px"
	width="100%"
	src="{{ config('shiny.shiny_url').'/'.config('shiny.shiny_app_name') }}"
>
```

6. Setup the Laravel page to listen to JavaScript Events coming from child pages (i.e. iframes):
	- On the page containing the iframe, add the following script:
```JavaScript
window.addEventListener("message", function(event) {

	// only accept messages from the shiny app
	// this script is written to be added to a Blade file, and so includes config() to get the correct Shiny URL
	if(event.origin !== "{{ config('shiny.shiny_url') }}") {
		return;
	}

	axios.post('/admin/shiny-auth', {'session': event.data})
		.catch((err) => {
			if(err.response.status == 403) {
				alert(err.message + ": " + err.response.data.message)
			}
	})
}, false)

```
4. Add the route and controller to respond to the `/admin/shiny-auth` endpoint:
	- Inside web.php, add the following route, and secure it however you need (e.g. with auth middleware)
		- `Route::post('admin/shiny-auth', [ShinyController::class, 'authenticate']);`
	- Create a ShinyController, and add the following authenticate() method:
```PHP

public function authenticate(Request $request) {

	$user = auth()->user();

	// Perform any other user authorisation checks here, e.g. check for the correct user roles or permissions. If the user authorisation fails, you can do something like abort(403);


	// get session ID to find correct file:
	$session = $request->input('session') ?? null;

	if(!$session) {
		return '';
	}

	// find the file written by the Shiny app (make sure to use the same path as used in Shiny.)
	$file = fopen(config('shiny.shiny_path') . "/.sessions/" . $session, "r");

	$url = [];

	while(! feof($file)) {
		$url[] = fgets($file);
	}

	fclose($file);


	// send post request to Shiny to let it know that the user is authenticated
	Http::post(str_replace("\n", "", $url[0])
		->throw();

	return response('success!', 200);

}
```

