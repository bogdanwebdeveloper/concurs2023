<?php 
session_start();
include 'dbconnect.php';
if (isset($_SESSION["username"]))
{   
    if(isset($_POST["submit"]) ) {

        $vkey = $_SESSION["vkey"];
        $code = $_POST["code"];
        $uid = $_SESSION["usersid"];
    
        if($vkey == $code){ 
            $sql = "UPDATE users SET verified=1 WHERE usersid=$uid";

            if (mysqli_query($conn, $sql)) {
                echo "Record updated successfully";
                mysqli_close($conn);
                header("location: ../index.php?emailverified");
              } else {
                echo "Error updating record: " . mysqli_error($conn);
              }

        }else{
            echo 'ERROR2';
        }
    } else {
       echo 'ERROR3';
    }
} else { 
    header("location: ../index.php?error=wtf");
}
?>