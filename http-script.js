const { exec } = require('child_process');
const fs = require('fs');

// Read URLs from a JSON file
const jsonFilePath = 'json/url.json';

// Ensure the results_http directory exists
const resultsDirectory = 'results';

if (!fs.existsSync(resultsDirectory)) {
  fs.mkdirSync(resultsDirectory);
}

fs.readFile(jsonFilePath, 'utf8', (readErr, data) => {
  if (readErr) {
    console.error('Error reading the JSON file:', readErr);
    return;
  }

  try {
    // Parse the JSON content into an array of URLs
    const urlArray = JSON.parse(data);

    // Prepare arrays to store results for each protocol
    const http1Results = [];
    const http2Results = [];

    // Counter to track processed URLs
    let processedCount = 0;

    // Iterate through each URL in the array
    urlArray.forEach((url) => {
      // Construct the cURL command with the current URL
      const curlCommand = `curl -I --http2 https://${url}`;

      // Execute the cURL command
      exec(curlCommand, (execErr, stdout, stderr) => {
        processedCount++;

        if (execErr) {
          console.error(`Error executing the command for ${url}: ${execErr.message}`);
          console.error(`Error STDERR: ${stderr}`);
          checkAndSaveResults();
          return;
        }

        // Divide the output into lines and capture the first line
        const lines = stdout.trim().split('\n');
        console.log(lines);

        // Build DNS and output information
        const dnsName = `DNS: ${url}`;
        const outputInfo = lines.join('\n');
        const resultInfo = `${dnsName}\n${outputInfo}\n\n\n`;

        // Determine the protocol used
        const protocol = lines[0].substring(0, 6);

        // Save the result in the appropriate array based on the protocol
        if (protocol.includes('HTTP/1')) {
          http1Results.push(resultInfo);
        } else if (protocol.includes('HTTP/2')) {
          http2Results.push(resultInfo);
        }

        checkAndSaveResults();
      });
    });

    function checkAndSaveResults() {
      // If all URLs have been processed, save the results to files
      if (processedCount === urlArray.length) {
        saveResultsToFile(http1Results, 'http1_results.txt');
        saveResultsToFile(http2Results, 'http2_results.txt');
      }
    }
  } catch (jsonError) {
    console.error('Error parsing JSON:', jsonError);
  }
});

function saveResultsToFile(resultsArray, fileName) {
  // The directory where you want to save the results
  const whereToSave = `results/${fileName}`;

  // Save the results to a file
  fs.writeFile(whereToSave, resultsArray.join('\n'), (writeErr) => {
    if (writeErr) {
      console.error(`Error while trying to save the file ${fileName}: ${writeErr.message}`);
      return;
    }
    console.log(`The file ${fileName} was saved in the following directory: ${whereToSave}`);
  });
}