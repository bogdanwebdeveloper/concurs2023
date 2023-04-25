<?php include 'header.php'; ?>
<?php
require 'includes/dbconnect.php';
if (isset($_SESSION["admin"]) && $_SESSION["admin"] != 0) echo '<div class="product-big-title-area">
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <div class="product-bit-title text-center">
                <h2>Admin dashboard</h2>
            </div>
        </div>
    </div>
</div>
</div>


<div class="single-product-area">
<div class="zigzag-bottom"></div>
<div class="container">
    <div class="row">
        <div class="col-md-3 col-sm-6">
            <div class="single-shop-product">
                <div class="product-upper">
                    <h1> ' . (mysqli_num_rows(mysqli_query($conn, "SELECT * from users"))) . ' </h1>
                </div>
                <h2>Registered accounts</h2>                  
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="single-shop-product">
                <div class="product-upper">
                    <h1> ' . (mysqli_num_rows(mysqli_query($conn, "SELECT * from users WHERE usersAdmin > 0"))) . '</h1>
                </div>
                <h2>Admins</h2>                    
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="single-shop-product">
                <div class="product-upper">
                    <h1>' . (mysqli_num_rows(mysqli_query($conn, "SELECT * from users WHERE usersPhone != 0"))) . '</h1>
                </div>
                <h2>Users with valid phone number</h2>                       
            </div>
        </div>
        <div class="col-md-3 col-sm-6">
            <div class="single-shop-product">
                <div class="product-upper">
                    <h1>0</h1>
                </div>
                <h2>Orders</h2>
                           
            </div>
        </div>
    </div>
    
</div>
</div>';
else echo '
    <div class="error-image">
        <h1>👨‍🔧</h1>
      </div>
      <div class="error-msg-container">
        <h1>Pagina nu este disponibilă pentru tine!</h1>
        <p>Nu deții permisiunile necesare pentru a folosi această pagină.</p>
    </div>

<style>.error-image {max-width: 720px;width: 90%;margin: auto;text-align: center;}.error-image h1 {font-size: 120px;margin: 48px auto 20px;}.error-msg-container {margin: 18px auto 30px auto;max-width: 800px;width: 80%;text-align: center;}.error-msg-container h1 {font-size: 56px;max-width: 560px;margin: auto auto 48px;}</style>' ?>

    <?php include 'footer.php'; ?>