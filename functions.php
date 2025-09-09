<?php
// Functions for CATEYE Web Scanner

// Global color variables
$white = "\e[0m";
$bold = "\e[1m";
$greenbg = "\e[42m";
$redbg = "\e[41m";
$bluebg = "\e[44m";
$cln = "\e[0m";
$lblue = "\e[94m";
$fgreen = "\e[92m";
$red = "\e[91m";
$blue = "\e[34m";
$magenta = "\e[35m";
$orange = "\e[38;5;208m";
$green = "\e[32m";
$grey = "\e[90m";
$cyan = "\e[36m";
$yellow = "\e[93m";

function getTitle($url) {
    $data = readcontents($url);
    $title = preg_match('/<title[^>]*>(.*?)<\/title>/ims', $data, $matches) ? $matches[1] : null;
    return $title;
}

function userinput($message) {
    global $white, $bold, $greenbg, $redbg, $bluebg, $cln, $lblue, $fgreen;
    $yellowbg = "\e[100m";
    $inputstyle = $cln . $bold . $lblue . "[#] " . $message . ": " . $fgreen;
    echo $inputstyle;
}

function WEBserver($urlws) {
    stream_context_set_default([
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    $wsheaders = get_headers($urlws, 1);
    if (is_array($wsheaders['Server'])) {
        $ws = $wsheaders['Server'][0];
    } else {
        $ws = $wsheaders['Server'];
    }
    if ($ws == "") {
        echo "\e[91mCould Not Detect\e[0m";
    } else {
        echo "\e[92m$ws \e[0m";
    }
}

function cloudflaredetect($reallink) {
    $urlhh = "http://api.hackertarget.com/httpheaders/?q=" . $reallink;
    $resulthh = file_get_contents($urlhh);
    if (strpos($resulthh, 'cloudflare') !== false) {
        echo "\e[91mDetected\n\e[0m";
    } else {
        echo "\e[92mNot Detected\n\e[0m";
    }
}

function CMSdetect($reallink) {
    $cmssc = readcontents($reallink);
    if (strpos($cmssc, '/wp-content/') !== false) {
        $tcms = "WordPress";
    } else {
        if (strpos($cmssc, 'Joomla') !== false) {
            $tcms = "Joomla";
        } else {
            $drpurl = $reallink . "/misc/drupal.js";
            $drpsc = readcontents("$drpurl");
            if (strpos($drpsc, 'Drupal') !== false) {
                $tcms = "Drupal";
            } else {
                if (strpos($cmssc, '/skin/frontend/') !== false) {
                    $tcms = "Magento";
                } else {
                    if (strpos($cmssc, 'content="WordPress') !== false) {
                        $tcms = "WordPress";
                    } else {
                        $tcms = "\e[91mCould Not Detect";
                    }
                }
            }
        }
    }
    return $tcms;
}

function advanced_CMSdetect($reallink) {
    $cmssc = readcontents($reallink);
    $cms_signatures = [
        'WordPress' => ['/wp-content/', 'content="WordPress', 'wp-includes/'],
        'Joomla' => ['/joomla/', 'Joomla!', 'content="Joomla'],
        'Drupal' => ['Drupal', 'drupal.js'],
        'Magento' => ['/skin/frontend/', 'Magento'],
        'Shopify' => ['shopify', 'cdn.shopify.com'],
        'Wix' => ['wix.com', 'wix-domain.net'],
        'Squarespace' => ['squarespace', 'static.squarespace.com'],
        'Blogger' => ['blogger.com', 'blogspot.com'],
        'Ghost' => ['ghost.org', 'content="Ghost'],
        'TYPO3' => ['typo3', 'TYPO3'],
        'PrestaShop' => ['prestashop', 'PrestaShop'],
        'OpenCart' => ['opencart', 'OpenCart'],
        'WooCommerce' => ['woocommerce', 'WooCommerce'],
        'BigCommerce' => ['bigcommerce', 'bigcommerce.com'],
        'Moodle' => ['moodle', 'Moodle'],
        'MediaWiki' => ['mediawiki', 'MediaWiki'],
        'phpBB' => ['phpbb', 'phpBB'],
    ];
    
    foreach ($cms_signatures as $cms => $signatures) {
        foreach ($signatures as $signature) {
            if (strpos($cmssc, $signature) !== false) {
                return $cms;
            }
        }
    }
    
    return "\e[91mCould Not Detect";
}

function robotsdottxt($reallink) {
    $rbturl = $reallink . "/robots.txt";
    $rbthandle = curl_init($rbturl);
    curl_setopt($rbthandle, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($rbthandle, CURLOPT_RETURNTRANSFER, TRUE);
    $rbtresponse = curl_exec($rbthandle);
    $rbthttpCode = curl_getinfo($rbthandle, CURLINFO_HTTP_CODE);
    if ($rbthttpCode == 200) {
        $rbtcontent = readcontents($rbturl);
        if ($rbtcontent == "") {
            echo "Found But Empty!";
        } else {
            echo "\e[92mFound \e[0m\n";
            echo "\e[36m\n-------------[ contents ]----------------  \e[0m\n";
            echo $rbtcontent;
            echo "\e[36m\n-----------[end of contents]-------------\e[0m";
        }
    } else {
        echo "\e[91mCould NOT Find robots.txt! \e[0m\n";
    }
}

function gethttpheader($reallink) {
    $hdr = get_headers($reallink);
    foreach ($hdr as $shdr) {
        echo "\n\e[92m\e[1m[i]\e[0m  $shdr";
    }
    echo "\n";
}

function extract_social_links($sourcecode) {
    global $bold, $lblue, $fgreen, $red, $blue, $magenta, $orange, $white, $green, $grey, $cyan;
    $fb_link_count = 0;
    $twitter_link_count = 0;
    $insta_link_count = 0;
    $yt_link_count = 0;
    $gp_link_count = 0;
    $pint_link_count = 0;
    $github_link_count = 0;
    $total_social_link_count = 0;

    $social_links_array = array(
        'facebook' => array(),
        'twitter' => array(),
        'instagram' => array(),
        'youtube' => array(),
        'google_p' => array(),
        'pinterest' => array(),
        'github' => array()
    );

    $sm_dom = new DOMDocument;
    @$sm_dom->loadHTML($sourcecode);
    $links = $sm_dom->getElementsByTagName('a');
    foreach ($links as $link) {
        $href = $link->getAttribute('href');
        if (strpos($href, "facebook.com/") !== false) {
            $total_social_link_count++;
            $fb_link_count++;
            array_push($social_links_array['facebook'], $href);
        } elseif (strpos($href, "twitter.com/") !== false) {
            $total_social_link_count++;
            $twitter_link_count++;
            array_push($social_links_array['twitter'], $href);
        } elseif (strpos($href, "instagram.com/") !== false) {
            $total_social_link_count++;
            $insta_link_count++;
            array_push($social_links_array['instagram'], $href);
        } elseif (strpos($href, "youtube.com/") !== false) {
            $total_social_link_count++;
            $yt_link_count++;
            array_push($social_links_array['youtube'], $href);
        } elseif (strpos($href, "plus.google.com/") !== false) {
            $total_social_link_count++;
            $gp_link_count++;
            array_push($social_links_array['google_p'], $href);
        } elseif (strpos($href, "github.com/") !== false) {
            $total_social_link_count++;
            $github_link_count++;
            array_push($social_links_array['github'], $href);
        } elseif (strpos($href, "pinterest.com/") !== false) {
            $total_social_link_count++;
            $pint_link_count++;
            array_push($social_links_array['pinterest'], $href);
        }
    }
    
    if ($total_social_link_count == 0) {
        echo $bold . $red . "[!] No Social Link Found In Source Code. \n\e[0m";
    } elseif ($total_social_link_count == "1") {
        echo $bold . $lblue . "[i] " . $fgreen . $total_social_link_count . $lblue . " Social Link Was Gathered From Source Code \n\n";
        display_social_links($social_links_array);
    } else {
        echo $bold . $lblue . "[i] " . $fgreen . $total_social_link_count . $lblue . " Social Links Were Gathered From Source Code \n\n";
        display_social_links($social_links_array);
    }
}

function display_social_links($social_links_array) {
    global $bold, $blue, $cyan, $magenta, $red, $orange, $grey, $white;
    
    foreach ($social_links_array['facebook'] as $link) {
        echo $bold . $blue . "[ facebook  ] " . $white . $link . "\n";
    }
    foreach ($social_links_array['twitter'] as $link) {
        echo $bold . $cyan . "[  twitter  ] " . $white . $link . "\n";
    }
    foreach ($social_links_array['instagram'] as $link) {
        echo $bold . $magenta . "[ instagram ] " . $white . $link . "\n";
    }
    foreach ($social_links_array['youtube'] as $link) {
        echo $bold . $red . "[  youtube  ] " . $white . $link . "\n";
    }
    foreach ($social_links_array['google_p'] as $link) {
        echo $bold . $orange . "[  google+  ] " . $white . $link . "\n";
    }
    foreach ($social_links_array['pinterest'] as $link) {
        echo $bold . $red . "[ pinterest ] " . $white . $link . "\n";
    }
    foreach ($social_links_array['github'] as $link) {
        echo $bold . $grey . "[  github   ] " . $white . $link . "\n";
    }
    echo "\n";
}

function extractLINKS($reallink) {
    global $bold, $lblue, $fgreen;
    $arrContextOptions = array(
        "ssl" => array(
            "verify_peer" => false,
            "verify_peer_name" => false,
        ),
    );
    $ip = str_replace("https://", "", $reallink);
    $lwwww = str_replace("www.", "", $ip);
    $elsc = file_get_contents($reallink, false, stream_context_create($arrContextOptions));
    $eldom = new DOMDocument;
    @$eldom->loadHTML($elsc);
    $elinks = $eldom->getElementsByTagName('a');
    $elinks_count = 0;
    foreach ($elinks as $ec) {
        $elinks_count++;
    }
    echo $bold . $lblue . "[i] Number Of Links Found In Source Code : " . $fgreen . $elinks_count . "\n";
    userinput("Display Links ? (Y/N) ");
    $bv_show_links = trim(fgets(STDIN, 1024));
    if ($bv_show_links == "y" or $bv_show_links == "Y") {
        foreach ($elinks as $elink) {
            $elhref = $elink->getAttribute('href');
            if (strpos($elhref, $lwwww) !== false) {
                echo "\n\e[92m\e[1m*\e[0m\e[1m $elhref";
            } else {
                echo "\n\e[38;5;208m\e[1m*\e[0m\e[1m $elhref";
            }
        }
        echo "\n";
    }
}

function readcontents($urltoread) {
    $arrContextOptions = array(
        "ssl" => array(
            "verify_peer" => false,
            "verify_peer_name" => false,
        ),
    );
    $filecntns = @file_get_contents($urltoread, false, stream_context_create($arrContextOptions));
    return $filecntns;
}

function MXlookup($site) {
    $Mxlkp = dns_get_record($site, DNS_MX);
    if (!empty($Mxlkp)) {
        $mxrcrd = $Mxlkp[0]['target'];
        $mxip = gethostbyname($mxrcrd);
        $mx = gethostbyaddr($mxip);
        $mxresult = "\e[1m\e[36mIP      :\e[32m " . $mxip . "\n\e[36mHOSTNAME:\e[32m " . $mx;
    } else {
        $mxresult = "\e[91mNo MX records found";
    }
    return $mxresult;
}

function bv_get_alexa_rank($url) {
    $xml = @simplexml_load_file("http://data.alexa.com/data?cli=10&url=" . $url);
    if (isset($xml->SD)) {
        return $xml->SD->POPULARITY->attributes()->TEXT;
    }
    return "N/A";
}

function bv_moz_info($url) {
    global $bold, $red, $fgreen, $lblue, $blue;
    if (file_exists("config.php")) {
        require("config.php");
        if (isset($accessID) && isset($secretKey) && 
            !empty($accessID) && !empty($secretKey) && 
            strpos($accessID, " ") === false && strpos($secretKey, " ") === false) {
            
            $expires = time() + 300;
            $SignInStr = $accessID . "\n" . $expires;
            $binarySignature = hash_hmac('sha1', $SignInStr, $secretKey, true);
            $SafeSignature = urlencode(base64_encode($binarySignature));
            $objURL = $url;
            $flags = "103079231492";
            $reqUrl = "http://lsapi.seomoz.com/linkscape/url-metrics/" . urlencode($objURL) . "?Cols=" . $flags . "&AccessID=" . $accessID . "&Expires=" . $expires . "&Signature=" . $SafeSignature;
            $opts = array(
                CURLOPT_RETURNTRANSFER => true
            );
            $curlhandle = curl_init($reqUrl);
            curl_setopt_array($curlhandle, $opts);
            $content = curl_exec($curlhandle);
            curl_close($curlhandle);
            $resObj = json_decode($content);
            if ($resObj) {
                echo $bold . $lblue . "[i] Moz Rank : " . $fgreen . ($resObj->{'umrp'} ?? 'N/A') . "\n";
                echo $bold . $lblue . "[i] Domain Authority : " . $fgreen . ($resObj->{'pda'} ?? 'N/A') . "\n";
                echo $bold . $lblue . "[i] Page Authority : " . $fgreen . ($resObj->{'upa'} ?? 'N/A') . "\n";
            } else {
                echo $bold . $red . "[!] Failed to retrieve MOZ data\n";
            }
        } else {
            echo $bold . $red . "\n[!] Some Results Will Be Omitted (Please Put Valid MOZ API Keys in config.php file)\n\n";
        }
    } else {
        echo $bold . $red . "\n[!] Config file not found. MOZ data will be omitted.\n\n";
    }
}

function sensitive_info_scan($reallink, $ipsl, $ip) {
    global $bold, $lblue, $fgreen, $red, $yellow, $green, $cln;
    
    echo $bold . $lblue . "[+] Scanning for sensitive information...\n\n" . $cln;
    
    // 1. Check for common sensitive files
    $sensitive_files = array(
        '.env', 'config.php', 'config.bak', 'config.inc.php', 'configuration.php',
        '.htaccess', '.htpasswd', 'robots.txt', 'web.config', 'phpinfo.php',
        'backup.zip', 'backup.sql', 'dump.sql', 'database.sql', 'backup.tar',
        'backup.tar.gz', 'error_log', 'access.log', '.git/config', '.DS_Store',
        'composer.json', 'package.json', 'yarn.lock', 'Gemfile', 'wp-config.php',
        'app.config', 'settings.py', 'config.json', 'credentials.json', 'secrets.yml'
    );
    
    echo $bold . $yellow . "[1] Checking for sensitive files:\n" . $cln;
    $found_files = array();
    
    foreach ($sensitive_files as $file) {
        $file_url = $reallink . '/' . $file;
        $headers = @get_headers($file_url);
        
        if ($headers && strpos($headers[0], '200')) {
            echo $bold . $red . "   [+] Found: " . $file_url . $cln . "\n";
            $found_files[] = $file_url;
            
            // Try to read the file content if it's text-based
            if (preg_match('/\.(php|txt|json|yml|js|env|sql|xml|html|log|inc|py|rb)$/i', $file)) {
                $content = @file_get_contents($file_url);
                if ($content && strlen($content) > 0 && strlen($content) < 50000) {
                    echo $bold . $lblue . "   [Content Preview]:\n" . $cln;
                    echo substr($content, 0, 500) . "\n\n";
                }
            }
        }
    }
    
    if (empty($found_files)) {
        echo $bold . $green . "   [-] No sensitive files found\n" . $cln;
    }
    
    // 2. Check for API keys and tokens in page source
    echo $bold . $yellow . "\n[2] Scanning for API keys and tokens:\n" . $cln;
    $page_content = readcontents($reallink);
    
    // Common API key patterns
    $patterns = array(
        '/[aA][pP][iI][_-]?[kK]e?y?[\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{20,60})/',
        '/[sS][eE][cC][rR][eE][tT][\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{20,60})/',
        '/[aA][cC][cC][eE][sS][sS][_-]?[tT]oken?[\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{20,60})/',
        '/[kK]e?y?[\"\'\\s]*[=:][\"\'\\s]*[sS][eE][cC][rR][eE][tT]_?([a-zA-Z0-9_\-]{20,60})/',
        '/[aA][pP][iI][_-]?[tT]oken?[\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{20,60})/',
        '/[pP][aA][sS][sS][wW]o?r?d?[\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{10,40})/',
        '/[aA][wW][sS][_-]?[aA][cC][cC][eE][sS][sS][_-]?[kK]e?y?[\"\'\\s]*[=:][\"\'\\s]*([A-Z0-9]{20})/',
        '/[aA][wW][sS][_-]?[sS][eE][cC][rR][eE][tT][_-]?[aA][cC][cC][eE][sS][sS][_-]?[kK]e?y?[\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{40})/',
        '/[sS][eE][cC][rR][eE][tT][_-]?[kK]e?y?[\"\'\\s]*[=:][\"\'\\s]*([a-zA-Z0-9_\-]{40,60})/'
    );
    
    $found_keys = array();
    foreach ($patterns as $pattern) {
        if (preg_match_all($pattern, $page_content, $matches)) {
            foreach ($matches[1] as $key) {
                if (!in_array($key, $found_keys)) {
                    echo $bold . $red . "   [+] Potential API key/token found: " . $key . $cln . "\n";
                    $found_keys[] = $key;
                }
            }
        }
    }
    
    if (empty($found_keys)) {
        echo $bold . $green . "   [-] No API keys or tokens found\n" . $cln;
    }
    
    // 3. Extract emails from page source
    echo $bold . $yellow . "\n[3] Extracting email addresses:\n" . $cln;
    if (preg_match_all('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', $page_content, $email_matches)) {
        $unique_emails = array_unique($email_matches[0]);
        foreach ($unique_emails as $email) {
            echo $bold . $lblue . "   [+] Email found: " . $email . $cln . "\n";
        }
    } else {
        echo $bold . $green . "   [-] No email addresses found\n" . $cln;
    }
    
    // 4. Check for hidden endpoints and admin panels
    echo $bold . $yellow . "\n[4] Checking for hidden endpoints and admin panels:\n" . $cln;
    $admin_paths = array(
        'admin', 'administrator', 'wp-admin', 'wp-login.php', 'login', 'logout',
        'signin', 'signout', 'dashboard', 'controlpanel', 'cp', 'manager',
        'management', 'console', 'backend', 'secure', 'private', 'config',
        'configuration', 'settings', 'options', 'debug', 'test', 'api',
        'oauth', 'auth', 'authentication', 'user', 'users', 'account',
        'accounts', 'admincp', 'administer', 'administration', 'phpmyadmin',
        'dbadmin', 'mysql', 'database', 'sql', 'webadmin', 'server', 'cpanel',
        'whm', 'webmail', 'mail', 'email', 'webmin', 'actuator', 'env', 'info',
        'status', 'health', 'metrics', 'trace', 'beans', 'dump', 'threaddump',
        'heapdump', 'logfile', 'jolokia', 'h2-console', 'graphql', 'graphiql',
        'voyager', 'playground', 'altair', 'swagger', 'swagger-ui', 'openapi',
        'redoc', 'api-docs', 'doc', 'docs', 'documentation', 'help', 'swagger.json',
        'swagger.yaml', 'openapi.json', 'openapi.yaml', 'api.json', 'api.yaml'
    );
    
    $found_endpoints = array();
    foreach ($admin_paths as $path) {
        $endpoint_url = $reallink . '/' . $path;
        $headers = @get_headers($endpoint_url);
        
        if ($headers && (strpos($headers[0], '200') || strpos($headers[0], '301') || strpos($headers[0], '302'))) {
            echo $bold . $red . "   [+] Found endpoint: " . $endpoint_url . " (" . $headers[0] . ")" . $cln . "\n";
            $found_endpoints[] = $endpoint_url;
        }
    }
    
    if (empty($found_endpoints)) {
        echo $bold . $green . "   [-] No hidden endpoints found\n" . $cln;
    }
    
    // 5. Check for common backup file patterns
    echo $bold . $yellow . "\n[5] Checking for backup files:\n" . $cln;
    $backup_patterns = array(
        'backup', 'backup.zip', 'backup.rar', 'backup.tar', 'backup.tar.gz',
        'backup.sql', 'database.zip', 'database.sql', 'dump.sql', 'dump.zip',
        'www.zip', 'public.zip', 'site.zip', 'web.zip', 'app.zip', 'data.zip',
        'db.zip', 'db.sql', 'db.dump', 'sql.zip', 'sql.sql', 'sql.dump',
        'backup_*.zip', 'backup_*.sql', 'backup_*.tar', 'backup_*.tar.gz',
        '*.bak', '*.old', '*.temp', '*.tmp', '*.backup', '*.save'
    );
    
    $found_backups = array();
    foreach ($backup_patterns as $pattern) {
        $backup_url = $reallink . '/' . $pattern;
        $headers = @get_headers($backup_url);
        
        if ($headers && strpos($headers[0], '200')) {
            echo $bold . $red . "   [+] Found backup file: " . $backup_url . $cln . "\n";
            $found_backups[] = $backup_url;
        }
    }
    
    if (empty($found_backups)) {
        echo $bold . $green . "   [-] No backup files found\n" . $cln;
    }
    
    // 6. Check for exposed directory listings
    echo $bold . $yellow . "\n[6] Checking for directory listings:\n" . $cln;
    $dirs_to_check = array('', 'images', 'uploads', 'files', 'assets', 'media', 'docs', 'downloads');
    
    foreach ($dirs_to_check as $dir) {
        $dir_url = $reallink . '/' . $dir;
        $content = @readcontents($dir_url);
        
        if ($content && (
            strpos($content, 'Index of /') !== false || 
            strpos($content, 'Directory listing for /') !== false ||
            strpos($content, '<title>Index of') !== false
        )) {
            echo $bold . $red . "   [+] Directory listing enabled: " . $dir_url . $cln . "\n";
        }
    }
    
    echo $bold . $green . "   [-] No directory listings found\n" . $cln;
    
    // Summary
    echo $bold . $yellow . "\n[+] Sensitive Information Scan Summary:\n" . $cln;
    echo $bold . $lblue . "   - Sensitive files found: " . count($found_files) . $cln . "\n";
    echo $bold . $lblue . "   - API keys/tokens found: " . count($found_keys) . $cln . "\n";
    echo $bold . $lblue . "   - Email addresses found: " . count($unique_emails ?? []) . $cln . "\n";
    echo $bold . $lblue . "   - Hidden endpoints found: " . count($found_endpoints) . $cln . "\n";
    echo $bold . $lblue . "   - Backup files found: " . count($found_backups) . $cln . "\n";
}

function resolve_url($url, $base) {
    // Return if already absolute URL
    if (parse_url($url, PHP_URL_SCHEME) != '') return $url;
    
    // Parse base URL and convert to arrays
    $base_parts = parse_url($base);
    
    // If relative URL has no path
    if ($url[0] == '/') {
        $path = $url;
    } else {
        // Parse base path
        $base_path = isset($base_parts['path']) ? $base_parts['path'] : '';
        
        // Strip current directory and parent directory references
        $base_path = preg_replace('#/[^/]*$#', '', $base_path);
        
        // Build absolute path
        $path = $base_path . '/' . $url;
    }
    
    // Build absolute URL
    $abs_url = $base_parts['scheme'] . '://' . $base_parts['host'] . $path;
    
    return $abs_url;
}

function advanced_link_crawl($html, $base_url) {
    $dom = new DOMDocument;
    @$dom->loadHTML($html);
    
    $internal_links = array();
    $external_links = array();
    $resource_links = array();
    
    // Get all links
    $links = $dom->getElementsByTagName('a');
    foreach ($links as $link) {
        $href = $link->getAttribute('href');
        if (!empty($href) && $href !== '#') {
            $absolute_url = resolve_url($href, $base_url);
            
            if (strpos($absolute_url, $base_url) !== false) {
                $internal_links[] = $absolute_url;
            } else {
                $external_links[] = $absolute_url;
            }
        }
    }
    
    // Get all resource links (images, scripts, styles)
    $tags = array('img' => 'src', 'script' => 'src', 'link' => 'href');
    foreach ($tags as $tag => $attribute) {
        $elements = $dom->getElementsByTagName($tag);
        foreach ($elements as $element) {
            if ($element->hasAttribute($attribute)) {
                $src = $element->getAttribute($attribute);
                if (!empty($src)) {
                    $absolute_src = resolve_url($src, $base_url);
                    $resource_links[] = $absolute_src;
                }
            }
        }
    }
    
    return array(
        'internal' => array_unique($internal_links),
        'external' => array_unique($external_links),
        'resources' => array_unique($resource_links)
    );
}

function display_all_links($links, $category) {
    global $bold, $green, $cln;
    
    if (count($links) > 0) {
        echo $bold . "\n[$category Links]\n";
        echo "================\n" . $cln;
        foreach ($links as $link) {
            echo $green . $link . $cln . "\n";
        }
    }
}
?>
