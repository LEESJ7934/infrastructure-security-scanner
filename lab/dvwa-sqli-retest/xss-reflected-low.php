<?php

// The greeting is rendered as text inside a <pre> element.
$name = $_GET['name'] ?? '';
if (!is_string($name) || $name === '') {
    return;
}

$escapedName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$html .= '<pre>Hello ' . $escapedName . '</pre>';
