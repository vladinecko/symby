<?php
/*
 * Created by Vladimir Olexa on 1/7/13.
 * Copyright 2012 Vladimir Olexa. All rights reserved.
 *
 * Symbolicates crash reports from iTunes App Store
 *
 * Usage: php symby.php crashreport.crash My App.app.dSYM
 *
 * */


$reader = new CrashReader($argv[1], $argv[2]);

$reader->readCrashReport();

/**
 * Wrapper class that is used as a utility to call and process all the juicy stuff inside LineDecoder
 */
class CrashReader {
    private $lineDecoder;
    private $crashContents;
    private $decodedLines = array();

	public function __construct($filename, $dSYMFilePath) {
        if (!file_exists($filename)) {
            $pathInfo = pathinfo(__FILE__);
            echo "\nYou provided an invalid crash report file.\nUsage: php {$pathInfo['basename']} myCrashReport.crash My App.app.dSYM\n\n";
            exit;
        }
        if (!file_exists($dSYMFilePath)) {
            $pathInfo = pathinfo(__FILE__);
            echo "\nYou provided an invalid dSYM file.\nUsage: php {$pathInfo['basename']} myCrashReport.crash My App.app.dSYM\n\n";
            exit;
        }

        $handle = fopen($filename, "r");
        $this->crashContents = fread($handle, filesize($filename));
        fclose($handle);

        $this->lineDecoder = new LineDecoder($dSYMFilePath, $this->getArchitecture(), $this->getAppName());
	}

    /**
     * Reads in the crash file and processes it line by line
     */
    function readCrashReport() {

		$lines = explode("\n", $this->crashContents);

        foreach ($lines as $line) {
            $this->decodedLines[] = $this->lineDecoder->decode($line);
		}

        $this->printAllLines();
	}

    /**
     * Tries to extract proper architecture from the crash file to feed into dwarfdump
     *
     * TODO: this could be more sophisticated and use other data to determine the arch so that we don't have to guess if not found
     *
     * @return string
     */
    function getArchitecture() {
        $appName = $this->getAppName();
        $pattern = "/\b{$appName}\b[[:space:]](armv[[:digit:]])/";

        if (preg_match($pattern, $this->crashContents, $matches)) {
            return $matches[1];
        }
        // Don't know, guessing 7
        return "armv7";
    }

    /**
     * Looks for App Name in the crash file to be used to detect which lines should be symbolicated
     *
     * @return string
     */
    function getAppName() {
        $pattern = "/Process:[[:space:]]+(.+)[[:space:]][[[:digit:]]+]/";
        if (preg_match($pattern, $this->crashContents, $matches)) {
            return $matches[1];
        }

        return "";
    }

    /**
     * Dumps the original crash report with app lines symbolicated
     */
    function printAllLines() {
        foreach ($this->decodedLines as $entry) {
            echo $entry . "\n";
        }
    }
}

/**
 * Does the actual decoding of crash report lines. It goes line by line and looks for one that matches $this->appName.
 * It then uses dwarfdump to symbolicate it.
 */
class LineDecoder {
    private $dSYMFilePath;
    private $appName;
    private $arch;

    public function __construct($dSYMFilePath, $arch, $appName) {
        $this->dSYMFilePath = $dSYMFilePath;
        $this->arch = $arch;
        $this->appName = $appName;
    }

    /**
     * Takes a $line of a crash report and looks to see if it's applicable to the app the crash report belongs to. If it
     * does, it attempts to symblicate the memory address associated to the line. If not, it simply dumps the line as is
     *
     * @param $line
     * @return string
     */
    function decode($line) {
        $pattern = "/^([[:digit:]]+)[[:space:]]+\b{$this->appName}\b[[:space:]]+(0x[a-fA-F0-9]{8}).*$/";

        if (preg_match($pattern, $line, $matches)) {
            $memoryAddress = $matches[2];
            $this->symbolicateMemoryAddress($memoryAddress);

            return $line . " " . $this->symbolicateMemoryAddress($memoryAddress);
        }

        return $line;
    }

    /**
     * Calls dwarfdump on the $memoryAddress provided and returns the proper symbol, if successful.
     *
     * @param $memoryAddress
     * @return string
     */
    function symbolicateMemoryAddress($memoryAddress) {
        $dwarfOutput = shell_exec("dwarfdump --lookup {$memoryAddress} --arch {$this->arch} {$this->dSYMFilePath}");
        $result = "";

        $pattern = "/\bstart_addr:[[:space:]]\b(0x[a-fA-F0-9]{8})[[:space:]](.+)/";
        if (preg_match($pattern, $dwarfOutput, $matches)) {
            $result .= $matches[2];
        }

        $lineNumPattern = "/\bLine table file\b:[[:space:]]'(.+)'[[:space:]]\bline\b[[:space:]]([[:digit:]]+), \bcolumn\b[[:space:]]([[:digit:]]+)/";

        if (preg_match($lineNumPattern, $dwarfOutput, $matches)) {
            $result .= " in {$matches[1]}, line {$matches[2]}, col {$matches[2]}";
        }

        return $result;
    }
}

?>