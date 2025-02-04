<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $url = filter_var($_POST["url"], FILTER_SANITIZE_URL);

    // Basic checks for phishing characteristics
    $isPhishing = false;
    $warningMessages = [];

    // Check if the URL contains an IP address instead of a domain name
    if (filter_var($url, FILTER_VALIDATE_IP)) {
        $isPhishing = true;
        $warningMessages[] = "The URL uses an IP address instead of a domain name.";
    }

    // Check for common phishing URL patterns
    if (preg_match('/\b(bank|login|secure|account|verify|paypal)\b/i', $url)) {
        $isPhishing = true;
        $warningMessages[] = "The URL contains suspicious keywords commonly used in phishing scams.";
    }

    // Check for a long URL
    if (strlen($url) > 75) {
        $isPhishing = true;
        $warningMessages[] = "The URL is unusually long, which is a common characteristic of phishing URLs.";
    }

    // Check for uncommon top-level domains
    $uncommonTLDs = ['.xyz', '.info', '.top', '.club'];
    foreach ($uncommonTLDs as $tld) {
        if (strpos($url, $tld) !== false) {
            $isPhishing = true;
            $warningMessages[] = "The URL uses an uncommon top-level domain: $tld.";
            break;
        }
    }

    // Output the results
    echo "<div style='font-family: Arial; padding: 20px;'>";
    echo "<h2>Phishing Detection Result</h2>";
    echo "<p><strong>URL Checked:</strong> " . htmlspecialchars($url) . "</p>";

    if ($isPhishing) {
        echo "<h3 style='color: red;'>Warning: The URL may be a phishing site!</h3>";
        echo "<ul>";
        foreach ($warningMessages as $message) {
            echo "<li>" . htmlspecialchars($message) . "</li>";
        }
        echo "</ul>";
    } else {
        echo "<h3 style='color: green;'>The URL appears to be safe.</h3>";
    }
    echo "</div>";
}
?>
