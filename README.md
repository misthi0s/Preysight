<head>
<h1 align=center>Preysight - Device Driver Anomaly Scanner</h1>
</head>

Preysight is a utility that will iterate through all currently loaded drivers and look for any potentially suspicious or malicious drivers, based on a certain set of criteria. The current set of criteria it looks for is as follows:

* Nonexistent driver file on the filesystem
* Abnormal file extension for a driver file
* Abnormal file path from which the driver was loaded
* Any drivers that are not digitally signed, either via embedded signature or catalog file
* Any drivers that were signed with an already expired signing certificate
* Any drivers that exist on the LOLDrivers list of vulnerable drivers

For a more detailed explanation of this criterion and for real-world examples of malware being found with the tool, please visit the supplemental [blog post](https://misthi0s.dev/posts/2026-07-12-driverchecker-malicious-drivers-tool/) on my website.

---

## Installation

Visit the Releases page of this repository for a pre-compiled binary of the tool.

If you want to  build the binary manually, simply open the `Preysight.slnx` file in Visual Studio and build the solution. The tool requires the following external libraries to build properly:

* nlohmann-json
* openssl

**vcpkg is required for these dependencies to be installed!** Building the solution should automatically pull and build the required packages, but if for some reason it doesn't, you can manually install them by running the following command from the project root:
```C:\<path>\<to>\vcpkg.exe install --triplet=x64-windows-static```

---

## Usage

Preysight currently supports the following parameters:

<table>
<tr>
<th>Parameter</th>
<th>Description</th>
</tr>
<tr>
<td>--no-network</td>
<td>Do not run any of the modules that require network access (IE, pulling the LOLDrivers list from the website)</td>
</tr>
<tr>
<td>--output {file_path}</td>
<td>Save the output of Preysight into a JSON-formatted file at {file_path} location.</td>
</tr>
</table>

---

## Tuning

Some legitimate results may be returned from running this tool, due to how certain applications load drivers or the drivers themselves being used in a legitimate manner. These results can be tuned out of the program, forcing it to not report on those specific items. Currently, the tuning list is hardcoded in a header file in the application, meaning the program will need to be re-built in order to add anything to the tuning lists. This may change in a future version to add portability, but for now, you can use the below instructions to add something to the tuning lists.

1). Open the `config.h` header file in the repository.<br>
2). There are currently two tuning lists: `fExtensionTuning` and `fExistsTuning`. These two lists tune results out of the `File Extension` and `File Exists` modules, respectively.<br>
3). Add the appropriate tuning item to the appropriate list, making sure that the backslashed (\) are properly escaped.<br>
4). Save the file and build the solution.

---

## Changelog
<h3>[v1.0] - 7/26/2026</h3>

* Renamed application to Preysight
* Added "driver signed with expired certificate" module
* Added the ability to save results to JSON file
* Reformatted console output to something cleaner and more readable

<h3>[v0.1] - 7/12/2026</h3>

* Initial publish

---

## Issues
<<<<<<< HEAD
If you run into any issues with Preysight, please feel free to open an issue in the repository.
=======
If you run into any issues with DriverChecker, please feel free to open an issue in the repository.
>>>>>>> c7059f330b420634062ab36c98e95f583169d34c
