<?php
	function emptyInputSignup($fullname, $email, $username, $password, $passwordRepeat, $telefon)
	{
		$result;
		if( empty($fullname) || empty($email) || empty($username) || empty($password) || empty($passwordRepeat) || empty($telefon))
		{
			$result = true;
		}
		else
		{
			$result = false;
		}
		return $result;
	}

	function emptyInputLogin($username, $password)
	{
		$result;
		if( empty($username) || empty($password) )
		{
			$result = true;
		}
		else
		{
			$result = false;
		}
		return $result;
	}
	
	function invalidUsername($username)
	{
		$result;
		if( !preg_match("/^[a-zA-Z0-9]*$/", $username) )
		{
			$result = true;
		}
		else
		{
			$result = false;
		}
		return $result;
	}
	
	function invalidEmail($email)
	{
		$result;
		if( !filter_var($email, FILTER_VALIDATE_EMAIL) )
		{
			$result = true;
		}
		else
		{
			$result = false;
		}
		return $result;
	}
	
	function passwordsMatch($password, $passwordRepeat)
	{
		$result;
		if( $password !== $passwordRepeat )
		{
			$result = true;
		}
		else
		{
			$result = false;
		}
		return $result;
	}
	function phonelong($telefon)
	{
		$result;
		if( strlen($telefon) > 12)
		{
			$result = true;
		}
		else
		{
			$result = false;
		}
		return $result;
	}
	
	function usernameExists($conn, $username)
	{
		$sql = "SELECT * FROM users WHERE usersUsername = ?;";
		
		$stmt = mysqli_stmt_init($conn);
		
		if( !mysqli_stmt_prepare($stmt, $sql) )
		{
			header("location: ../signup.php?error=stmtfailed");
			exit();
		}
		
		mysqli_stmt_bind_param($stmt, "s", $username);
		mysqli_stmt_execute($stmt);
		
		$resultData = mysqli_stmt_get_result($stmt);
		
		mysqli_stmt_close($stmt);
		
		if( $row = mysqli_fetch_assoc($resultData) )
		{
			return $row;
		}
		else
		{
			return false;
		}
	}
	
	function emailExists($conn, $email)
	{
		$sql = "SELECT * FROM users WHERE usersEmail = ?;";
		
		$stmt = mysqli_stmt_init($conn);
		
		if( !mysqli_stmt_prepare($stmt, $sql) )
		{
			header("location: ../signup.php?error=stmtfailed");
			exit();
		}
		
		mysqli_stmt_bind_param($stmt, "s", $email);
		mysqli_stmt_execute($stmt);
		
		$resultData = mysqli_stmt_get_result($stmt);
		
		mysqli_stmt_close($stmt);
		
		if( $row = mysqli_fetch_assoc($resultData) )
		{
			return $row;
		}
		else
		{
			return false;
		}
	}
	
	function createUser($conn, $fullname, $email, $username, $password, $telefon, $vkey)
	{
		$sql = "INSERT INTO users (usersUsername, usersEmail, usersPassword, usersRealname, usersPhone, vkey) VALUES (?, ?, ?, ?, ?, ?);";
		
		$stmt = mysqli_stmt_init($conn);
		
		if ( !mysqli_stmt_prepare($stmt, $sql) )
		{
			header("location: ../signup.php?error=stmtfailed");
			exit();
		}
		
		$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
		
		mysqli_stmt_bind_param($stmt, "ssssss", $username, $email, $hashedPassword, $fullname, $telefon, $vkey);
		
		mysqli_stmt_execute($stmt);
		mysqli_stmt_close($stmt);
		header("location: ../login.php?error=none");
		exit();
	}
	
	function loginUser($conn, $username, $password)
	{
		$usernameExists = usernameExists($conn, $username);
		
		if ($usernameExists === false)
		{
			header("location: ../login.php?error=wronglogin");
			exit();
		}
		
		$hashedPassword = $usernameExists["usersPassword"];
		$checkPassword = password_verify($password, $hashedPassword);
		
		if ( $checkPassword === false )
		{
			header("location: ../login.php?error=wronglogin");
			exit();
		}
		else if ( $checkPassword === true )
		{
			session_start();
			$_SESSION["usersid"] = $usernameExists["usersId"];
			$_SESSION["username"] = $usernameExists["usersUsername"];
			$_SESSION["realname"] = $usernameExists["usersRealname"];
			$_SESSION["telefon"] = $usernameExists["usersPhone"];
			$_SESSION["vkey"] = $usernameExists["vkey"];
			$_SESSION["registerDate"] = $usernameExists["registerDate"];
			$_SESSION["verified"] = $usernameExists["verified"];
			$_SESSION["email"] = $usernameExists["usersEmail"];
			$_SESSION["admin"] = $usernameExists["usersAdmin"];

			header("location: ../index.php");
			exit();
		}
	}