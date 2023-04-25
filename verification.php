<?php require"header.php"?>
<div class="container mt-3" style="margin: 2em; display: flex; justify-content: center; align-items: center; margin-top: 20em; margin-bottom: 15em;">
    <div class="card">
        <div class="card-header text-center textblack">
           <p style="font-weight: bolder;"> User Account Activation by Email Verification</p></div>
        <div class="card-body">
            <form method="post" action="includes/codeeq.php">
                <label for="fname" class="textblack" style="color: #A42CD6">Insert the code received in the email</label><br>
                <input type="text" id="code" name="code" style="margin-top: 0.5em;"><br>
                <input type="submit" value="Submit" name="submit" style="margin-top: 1.5em; background: #A42CD6; color: white; height: 3em; width: 5em; border: none; border-radius: 10px;">
            </form>
        </div>
    </div>
</div>
<?php
include 'footer.php'; ?>