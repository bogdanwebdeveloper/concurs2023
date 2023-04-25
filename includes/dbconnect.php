<?php
$dbServer = "localhost";
$dbUsername = "root";
$dbPassword = "cbogdan";
$dbName = "webivot";

$conn = mysqli_connect($dbServer, $dbUsername, $dbPassword, $dbName);

if (!$conn) {
	die("Connection failed: " . mysqli_connect_error());
}
