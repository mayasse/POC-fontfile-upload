const express = require('express');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const cmd = require('node-cmd');
const opentype = require('opentype.js');
const md5 = require('md5');
const app = express();
const app2 = express();
const app3 = express();

 
// default options
app.use(
    fileUpload(
        {
            limits: {
                fileSize: 50 * 1024 * 1024
            }
        }
    )
);
 
app.post('/upload', function(req, res) {
    if (!req.files) {
        return res.status(400).send('No files were uploaded.');
    }
 
    // The name of the input field (i.e. "sampleFile") is used to retrieve the uploaded file
    let sampleFile = req.files.sampleFile;

    // Get md5 as a "unique name"
    var md5Hash = md5(sampleFile.data);
    var fullFileName = path.join(__dirname + '/' + md5Hash);
    var fullLogFileName = fullFileName + ".log";
    var result = null;
    var status = 200;

        // Use the mv() method to place the file somewhere on your server
    sampleFile.mv(
        fullFileName,
        function(err) {
            if (err) {
                return res.status(500).json({"error": err});
            } else {
                // Delete any log file that may exist from ESET
                try {
                    fs.unlinkSync(fullLogFileName);
                } catch (err) {
                    result = {};
                    status = 200;
                }

                // Use command line to check the file using ESET and search for results in the output file
                var esets_scan_command = '/Applications/ESET\\ Endpoint\\ Security.app/Contents/MacOS/esets_scan'
                    + ' -f ' + fullLogFileName + ' ' + fullFileName;
                var search_results_command = 'grep \'name=\"\' '
                    + fullLogFileName + ' | egrep -o \'threat=\"[^\"]+|info=\"[^\"]+\'';

                cmd.get(
                    esets_scan_command + ";" + search_results_command,
                    function(err, data, stderr){
                        // Delete any log file that may exist from ESET
                        try {
                            fs.unlinkSync(fullLogFileName);
                        } catch (err) {
                            result = {};
                            status = 200;
                        }
                        if (stderr) {
                            // stderr output means that the ESET command failed
                            result = {"error": "Failed AV scan", "stderr": stderr};
                            status = 401;
                        } else if (!err && data && data.length > 0) {
                            // Returning data means that grep found a problem in the log file
                            result = {"error": "Failed AV scan", "data": data};
                            status = 401;
                        } else {
                            // At this point we have a "clean" file
                            var font = null;
                            try {
                                // Read font from posted input stream
                                font = opentype.parse(sampleFile.data.buffer);
                                // Read font from file
                                //font = opentype.loadSync(fullFileName);
                            } catch (err) {
                                // A thrown error means that the font format is not OK
                                result = {"error": "Failed format", "throwable": err};
                                status = 401;
                            } finally {
                                if (font) {
                                    if (!font.supported) {
                                        // "supported" flag = 0 means that the font format is not OK
                                        result = {"error": "Failed format: font is not supported"};
                                        status = 401;
                                    } else {
                                        result = {"names": font.names, "numGlyphs": font.numGlyphs};
                                        status = 200;
                                    }
                                }
                            }
                        }
                        return res.status(status).json(result);
                    }
                );
            }
        }
    );
});


app.get('/picker', function(req, res) {
    res.sendFile(path.join(__dirname + '/sampleUI.html'));
});
app.get('/render', function(req, res) {
    res.sendFile(path.join(__dirname + '/renderFont.html'));
});
app.get('/file/:fileMd5', function (req,res) {
    res.sendFile(path.join(__dirname + "/" + req.params.fileMd5));
})
app.listen(8000);

app2.use(bodyParser.urlencoded({ extended: true }));
app2.post('/create', function(req, res) {
    if (!req.body.fileText || !req.body.fileName) {
        return res.status(400).send('No file was created.');
    }

    fs.writeFileSync(
        path.join(__dirname + '/' + req.body.fileName),
        req.body.fileText.trim()
    )
    res.send('File created!');
});

app2.listen(8001);

app3.use(bodyParser.urlencoded({ extended: true }));
app3.post('/check', function(req, res) {
    if (!req.body.fileName) {
        return res.status(400).send('No file was checked');
    }
    var fileName = req.body.fileName;
    var logFileName = fileName + ".log";
    var fullFileName = path.join(__dirname + '/' + fileName);
    var fullLogFileName = path.join(__dirname + '/' + logFileName);

    var result = null;
    var status = 200;

    //console.log(fileName, logFileName, fullFileName, fullLogFileName);

    // Delete any log file that may exist
    try {
        fs.unlinkSync(fullLogFileName);
    } catch (err) {
        result = {};
        status = 200;
    }

    // Use command line to check the file using ESET
    var esets_scan_command = '/Applications/ESET\\ Endpoint\\ Security.app/Contents/MacOS/esets_scan'
        + ' -f ' + fullLogFileName + ' ' + fullFileName;
    var search_results_command = 'grep \'name=\"\' '
        + fullLogFileName + ' | egrep -o \'threat=\"[^\"]+|info=\"[^\"]+\'';

    // Use command line to get the results of the check
    cmd.get(
        esets_scan_command + ";" + search_results_command,
        function(err, data, stderr){
            if (stderr) {
                // stderr output means that the ESET command failed
                result = {"error": "Failed AV scan", "stderr": stderr};
                status = 401;
            // } else if (err) {
            //     // An error means that grep failed to find a problem in the log file
            //     result = "AV scan ok";
            //     status = 200;
            } else if (!err && data && data.length > 0) {
                // Returning data means that grep found a problem in the log file
                result = {"error": "Failed AV scan", "data": data};
                status = 401;
            } else {
                var font = null;
                try {
                    font = opentype.loadSync(fullFileName);
                } catch (err) {
                    // A thrown error means that the font format is not OK
                    result = {"error": "Failed format", "throwable": err};
                    status = 401;
                } finally {
                    if (font) {
                        if (!font.supported) {
                            // "supported" flag = 0 means that the font format is not OK
                            result = {"error": "Failed format: font is not supported"};
                            status = 401;
                        } else {
                            result = {"names": font.names, "numGlyphs": font.numGlyphs};
                            status = 200;
                        }
                    }
                }
            }
            return res.status(status).json(result);
        }
    );
});
app3.listen(8002);

function parseFontStream(buffer) {
    return opentype.parse(buffer);
}






