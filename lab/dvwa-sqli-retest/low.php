<?php

// Local replacement for the DVWA Low SQL Injection handler.
if (!isset($_REQUEST['Submit'])) {
    return;
}

$rawId = $_REQUEST['id'] ?? null;
$id = is_string($rawId) && preg_match('/\A[0-9]+\z/', $rawId)
    ? filter_var(ltrim($rawId, '0'), FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 2147483647],
    ])
    : false;

if ($id === false) {
    http_response_code(400);
    $html .= '<p>Invalid user ID.</p>';
    return;
}

$sql = 'SELECT first_name, last_name FROM users WHERE user_id = :user_id';

try {
    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            $statement = $db->prepare($sql);
            $statement->bindValue(':user_id', $id, PDO::PARAM_INT);
            $statement->execute();
            $row = $statement->fetch(PDO::FETCH_ASSOC);
            break;

        case SQLITE:
            $statement = $sqlite_db_connection->prepare($sql);
            $statement->bindValue(':user_id', $id, SQLITE3_INTEGER);
            $result = $statement->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            $result->finalize();
            break;

        default:
            throw new RuntimeException('Unsupported SQL Injection lab database');
    }
} catch (Exception $error) {
    error_log('DVWA SQLi retest: user lookup failed');
    http_response_code(500);
    $html .= '<p>User lookup failed.</p>';
    return;
}

if ($row !== false) {
    $first = htmlspecialchars($row['first_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $last = htmlspecialchars($row['last_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}
