<?php 
/*
Template Name:找回密码
*/
error_reporting(0);
global $wpdb, $user_ID;
function tg_validate_url() {   
	global $post;   
	$page_url = esc_url(get_permalink( $post->ID )); 
	$urlget = strpos($page_url, "?");   
	if ($urlget === false) {   
		$concate = "?";   
	}else{   
		$concate = "&";   
	}   
	return $page_url.$concate;
}
if(!$user_ID){
	if($_POST['action'] == "tg_pwd_reset"){ //判断是否为请求重置密码   
    if ( !wp_verify_nonce( $_POST['tg_pwd_nonce'], "tg_pwd_nonce")) { //检查随机数   
        exit("不要开玩笑");   
    }   
    if(empty($_POST['user_input'])) {   
        echo "<div class='error'>请输入用户名或E-mail地址</div>";   
        exit();   
    }
    //过滤提交的数据   
    $user_input = $wpdb->escape(trim($_POST['user_input']));
    if ( strpos($user_input, '@') ) { //判断用户提交的是邮件还是用户名   
        $user_data = get_user_by_email($user_input); //通过Email获取用户数据   
        if(empty($user_data) || $user_data->caps[administrator] == 1) { //排除管理员   
            echo "<div class='error'>无效的E-mail地址!</div>";   
            exit();   
        }   
    } else {   
        $user_data = get_userdatabylogin($user_input); //通过用户名获取用户数据   
        if(empty($user_data) || $user_data->caps[administrator] == 1) { //排除管理员   
            echo "<div class='error'>无效的用户名!</div>";   
            exit();   
        }   
    } 
    $user_login = $user_data->user_login;   
    $user_email = $user_data->user_email;
    $key = $wpdb->get_var($wpdb->prepare("SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s", $user_login)); //从数据库中获取密匙   
    if(empty($key)) { //如果为空   
        //generate reset keys生成 keys   
        $key = wp_generate_password(20, false); //生成一个20位随机密码用做密匙   
        $wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $user_login)); //更新到数据库   
    }
    //邮件内容   
    $message = __('有人提交了重置下面账户密码的请求:') . "\r\n\r\n";   
    $message .= get_option('siteurl') . "\r\n\r\n";   
    $message .= sprintf(__('用户名: %s'), $user_login) . "\r\n\r\n";   
    $message .= __('如果不是您本人操作，请忽略这个邮件即可.') . "\r\n\r\n";   
    $message .= __('如果需要重置密码，请访问下面的链接:') . "\r\n\r\n";   
    $message .= tg_validate_url() . "action=reset_pwd&key=$key&login=" . rawurlencode($user_login) . "\r\n"; //注意tg_validate_url()，注意密码重置的链接地址，需要action\key\login三个参数
    if ( $message && !wp_mail($user_email, '密码重置请求', $message) ) {   
        echo "<div class='error'>邮件发送失败-原因未知。</div>";   
        exit();   
    } else {   
        echo "<div class='success'>我们已经在给你发送的邮件中说明了重置密码的各项事宜，请注意查收。</div>";   
        exit();   
    }   
} else {   
	get_header();
?>
<div id="container"> 
	<div class="ex-login">
	<?php if ( have_posts() ) : while ( have_posts() ) : the_post(); ?>
		<h3>输入用户名或邮箱地址</h3>
        <form class="user_form" id="wp_pass_reset" action="" method="post">  
        <input type="text" class="text" name="user_input" value="" /><br />   
        <input type="hidden" name="action" value="tg_pwd_reset" />   
        <input type="hidden" name="tg_pwd_nonce" value="<?php echo wp_create_nonce("tg_pwd_nonce"); ?>" />   
        <!--wp_create_nonce函数创建随机数，用于安全验证-->   
        <input type="submit" id="submitbtn" class="submit" name="submit" value="找回密码" />   
        </form>   
        <div id="result"></div> <!-- To hold validation results -->   
        <script type="text/javascript">   
        $("#wp_pass_reset").submit(function() {    
            $('#result').html('<span class="loading">Validating...</span>').fadeIn();   
            var input_data = $('#wp_pass_reset').serialize();   
            $.ajax({   
                type: "POST",   
                url:  "<?php echo get_permalink( $post->ID ); ?>",   
                data: input_data,   
                success: function(msg){   
                    $('.loading').remove();   
                    $('<div>').html(msg).appendTo('div#result').hide().fadeIn('slow');   
                }   
            });   
            return false;   
        });   
        </script>   
    <?php endwhile; else : ?>   
    <h2><?php _e('没有找到'); ?></h1>          
    <?php endif; ?>  
    <?php
    if(isset($_GET['key']) && $_GET['action'] == "reset_pwd") { //如果存在key且action参数似乎reset_pwd   
        $reset_key = $_GET['key']; //获取密匙   
        $user_login = $_GET['login']; //获取用户名   
        $user_data = $wpdb->get_row($wpdb->prepare("SELECT ID, user_login, user_email FROM $wpdb->users WHERE user_activation_key = %s AND user_login = %s", $reset_key, $user_login));   
        //通过key和用户名验证数据   
 
        $user_login = $user_data->user_login;   
        $user_email = $user_data->user_email;   
        if(!empty($reset_key) && !empty($user_data)) {   
            $new_password = wp_generate_password(7, false); //生成7位随机密码   
            //echo $new_password; exit();   
            wp_set_password( $new_password, $user_data->ID ); //重置密码   
            //通过邮件将密码发送给用户   
            $message = __('账户的新密码为:') . "\r\n\r\n";   
            $message .= get_option('siteurl') . "\r\n\r\n";   
            $message .= sprintf(__('用户名: %s'), $user_login) . "\r\n\r\n";   
            $message .= sprintf(__('密码: %s'), $new_password) . "\r\n\r\n";   
            $message .= __('你可以使用你的新密码通过下面的链接登录: ') . get_option('siteurl')."/login" . "\r\n\r\n";   
            if ( $message && !wp_mail($user_email, '密码重置请求', $message) ) {   
                echo "<div class='error'>邮件发送失败-原因未知</div>";   
                exit();   
            } else {   
                $redirect_to = tg_validate_url()."action=reset_success";//跳转到登陆成功页面(还是本页面地址)   
                wp_safe_redirect($redirect_to);   
                exit();   
            }   
 
        } else{   
            exit('无效的key.');   
        }   
    }  
 
if(isset($_GET['action']) && $_GET['action'] == "reset_success") { //如果动作为reset_success就是成功了哇   
   echo '<div class="success">密码重置成功，已经通过邮件发送给您，请查收。</div>';
}  
?>	
	</div>
</div>
<?php
	}
    }else{   
        wp_redirect(home_url()); 
		exit;
    }   
get_footer();
?>