# http-script

A script to check the HTTP protocol used by websites getting the URLs that will be checked from a JSON file.

This is used to get a lot of URLs and check them to see which ones use HTTP/2 and may be vulnerable to Rapid Reset Attack - CVE-2023-44487

## Enviroment

You must have cURL and nghttp-2 installed.

You can install both in Linux using the script in <a href="https://gist.github.com/jjpeleato/3327c2e38fc0fea7d6602401f9849809">this repository!</a>

You must have WHOIS package installed, you can do it on linux using the command "sudo apt install whois"

## Use

To use the script, you should open the "url.json" file inside the folder "json" and put the URLs you would like to check.

The URL must <b>NOT</b> have the "https://"

For example: "www.google.com"

## Output

As output, you're gonna receive all the infos about the protocol used for eache URL in the terminal. These infos about the URL received by cURL will be saved in two different files, "http1_results.txt" for the URLs that support HTTP/1 and "http2_results.txt" for the URLs that support HTTP/2, both are going to be in the folder "results"

## Tip

If you just want to check a single URL, I recommend you to use my other script that you put the URL in the command, without JSON file and stuff. 

You can check it <a href="https://github.com/ramonzx6/http-script">here!</a>
