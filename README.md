# http-checker-script

A script to check the HTTP protocol used by websites getting the URLs that will be checked from a JSON file.

## Enviroment

You must have cURL and nghttp-2 installed.

You can install both in Linux using the script in <a href="https://gist.github.com/jjpeleato/3327c2e38fc0fea7d6602401f9849809">this repository!</a>

If you use Windows, you can use it via WSL, which is a native way to use Linux in Windows. I used WSL while I was building and using the script.

## Use

To use the script, you should open the "url.json" file inside the folder "json" and put the URLs you would like to check.

The URL must <b>NOT</b> have the "https://"

For example: "www.google.com"

## Output

As output, you're gonna receive all the infos about the protocol used for each URL in the terminal. These infos about the URL received by cURL will be saved in two different files, "http1_results.txt" for the URLs that support HTTP/1 and "http2_results.txt" for the URLs that support HTTP/2, both are going to be in the folder "results"
