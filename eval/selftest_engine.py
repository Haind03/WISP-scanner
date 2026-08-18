#!/usr/bin/env python3
"""Regression self-test for the WISP rule-driven taint engine.

Encodes the behaviors the recall work relies on, so a future change (or a
Stage-4 auto-synthesized rule) cannot silently break them. This is also the
false-positive regression gate the rule-mining loop runs before admitting a
new rule: it must keep every TRUE case detected and every SAFE case silent.

    python3 selftest_engine.py        # exits 0 on pass, 1 on regression

No network, no API cost.
"""
from __future__ import annotations
import sys
import tempfile
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wisp.engine import taint_engine as te


# (label, php, expected_classes_present, must_be_silent_substrings)
CASES = [
    ("cross-function SQLi", """<?php
function run_query($sql){ global $wpdb; $wpdb->query($sql); }
function build($id){ return "SELECT * FROM t WHERE id=".$id; }
function handler(){ $id=$_GET['id']; run_query(build($id)); }
""", {"sqli"}, []),

    ("reflected XSS", """<?php
function show(){ echo $_REQUEST['name']; }
""", {"xss"}, []),

    ("LFI include", """<?php
function tpl(){ include $_GET['tpl']; }
""", {"lfi"}, []),

    ("sanitized query is SILENT", """<?php
function safe(){ global $wpdb; $id=(int)$_GET['id']; $wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id=%d",$id)); }
""", set(), ["sqli"]),

    ("taint through helpers (.=, sprintf, str_replace, trim, foreach)", """<?php
function a(){ $x=$_GET['a']; $y=''; $y.=$x; echo $y; }
function c(){ echo sprintf("hi %s", $_GET['c']); }
function h(){ echo str_replace('x','y',$_GET['h']); }
function j(){ include trim($_GET['p']); }
function f(){ foreach($_GET as $v){ echo $v; } }
""", {"xss", "lfi"}, []),

    ("RCE via call_user_func", """<?php
function g(){ $cb=$_GET['fn']; call_user_func($cb); }
""", {"rce"}, []),

    ("filter_input is a direct request source", """<?php
function fi(){ echo filter_input(INPUT_GET, 'html'); }
""", {"xss"}, []),

    ("validated numeric filter_input is SILENT", """<?php
function fi_safe(){
  echo filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
  system(filter_input(INPUT_GET, 'n', FILTER_VALIDATE_INT));
}
""", set(), ["xss", "rce"]),

    ("persistent option read reaches code sink", """<?php
function stored_code(){ $settings=get_option('plugin_settings'); eval($settings['code']); }
""", {"rce"}, []),

    ("persistent option path reaches filesystem sink", """<?php
function stored_path(){ $path=get_option('plugin_feed_path'); unlink($path); }
""", {"lfi"}, []),

    ("source-like custom method names are SILENT", """<?php
class LocalConfig {
  function get_option($ignored=''){ return 'fixed'; }
  function getenv($ignored=''){ return 'fixed'; }
  function run(){
    eval($this->get_option($_GET['x']));
    eval($this->getenv($_GET['x']));
  }
}
""", set(), ["rce"]),

    ("unknown receiver cannot borrow unrelated sanitizer summary", """<?php
class LocalCleaner { function clean($value){ return esc_html($value); } }
function render_external($external){ echo $external->clean($_GET['html']); }
""", {"xss"}, []),

    ("unresolved inherited call cannot borrow unrelated summary", """<?php
class ChildCleaner extends ExternalBase {
  function render(){ echo $this->clean($_GET['html']); }
}
class UnrelatedCleaner { function clean($value){ return esc_html($value); } }
""", {"xss"}, []),

    ("namespaced source-like free function uses its summary", """<?php
namespace PluginLocal;
function get_option($ignored=''){ return 'fixed'; }
function getenv($ignored=''){ return 'fixed'; }
function run(){ eval(get_option($_GET['x'])); eval(getenv($_GET['x'])); }
""", set(), ["rce"]),

    ("explicit root source bypasses namespace-local shadow", """<?php
namespace PluginLocal;
function get_option($ignored=''){ return 'fixed'; }
function root_read(){ eval(\\get_option('plugin_code')); }
""", {"rce"}, []),

    ("unsafe helper remains distinct across namespaces", """<?php
namespace SafeNs { function normalize($v){ return 'fixed'; } }
namespace UnsafeNs {
  function normalize($v){ return $v; }
  function run(){ echo normalize($_GET['x']); }
}
""", {"xss"}, []),

    ("safe helper is not polluted across namespaces", """<?php
namespace UnsafeNs { function normalize($v){ return $v; } }
namespace SafeNs {
  function normalize($v){ return 'fixed'; }
  function run(){ echo normalize($_GET['x']); }
}
""", set(), ["xss"]),

    ("request environment is scoped; PATH is not request data", """<?php
function host_command(){ system(getenv('HTTP_HOST')); }
""", {"rce"}, []),

    ("non-request environment is SILENT", """<?php
function path_command(){ system(getenv('PATH')); }
""", set(), ["rce"]),

    ("literal callbacks with tainted data are SILENT", """<?php
function callback_data(){
  array_map('trim', $_POST['items']);
  usort($_POST['items'], 'compare_items');
  call_user_func('trim', get_option('plugin_value'));
}
""", set(), ["rce"]),

    ("literal pass-through helpers do not create taint", """<?php
function no_source(){ echo wp_unslash('fixed'); echo apply_filters('label', 'fixed'); }
""", set(), ["xss"]),

    ("branch-join: else-branch reassignment must not kill taint", """<?php
function bj(){ $t=$_GET['x']; if(preg_match('/^.*$/',$t)==1){ $t=$t; } else { $t=""; }
global $wpdb; $wpdb->query("SELECT * FROM t WHERE a='".$t."'"); }
""", {"sqli"}, []),

    ("context-aware: wrong-context sanitizer does NOT clean", """<?php
function a(){ echo esc_sql($_GET['x']); }
function b(){ global $wpdb; $wpdb->query(esc_html($_GET['id'])); }
""", {"xss", "sqli"}, []),

    ("context-aware: right-context sanitizer IS silent", """<?php
function a(){ echo esc_html($_GET['x']); }
function b(){ global $wpdb; $wpdb->query(esc_sql($_GET['id'])); }
function c(){ echo intval($_GET['n']); }
""", set(), ["xss", "sqli"]),

    ("helper return keeps sanitizer class across summary", """<?php
function html_only($value){ return esc_html($value); }
function query(){ global $wpdb; $wpdb->query(html_only($_GET['q'])); }
""", {"sqli"}, []),

    ("helper return stays safe for its sanitizer class", """<?php
function html_only($value){ return esc_html($value); }
function render(){ echo html_only($_GET['html']); }
""", set(), ["xss"]),

    ("transitive helper keeps sanitizer class", """<?php
function html_safe_inner($value){ return esc_html($value); }
function html_safe_outer($value){ return html_safe_inner($value); }
function render_safe_outer(){ echo html_safe_outer($_GET['html']); }
""", set(), ["xss"]),

    ("assigned helper return keeps sanitizer class", """<?php
function assigned_html_safe($value){ return esc_html($value); }
function render_assigned_safe(){ $html=assigned_html_safe($_GET['html']); echo $html; }
""", set(), ["xss"]),

    ("transitive helper propagates sanitizer invalidation", """<?php
function decode_inner($value){ return htmlspecialchars_decode($value); }
function decode_outer($value){ return decode_inner($value); }
function render_decoded(){ echo decode_outer(esc_html($_GET['html'])); }
""", {"xss"}, []),

    ("transitive helper propagates persistent source", """<?php
function stored_inner(){ return get_option('plugin_code'); }
function stored_outer(){ return stored_inner(); }
function run_stored(){ eval(stored_outer()); }
""", {"rce"}, []),

    ("assigned persistent helper stays scoped to executable sink", """<?php
function stored_setting(){ return get_option('plugin_code'); }
function use_stored_setting(){
  $setting=stored_setting();
  echo $setting;
  eval($setting);
}
""", {"rce"}, ["xss"]),

    ("persistent call cannot mask unrelated request return", """<?php
function mixed_source(){ get_option('unused'); return $_GET['html']; }
function render_mixed_source(){ echo mixed_source(); }
""", {"xss"}, []),

    ("HTML decoder does not widen persistent-source policy", """<?php
function stored_label(){ return get_option('plugin_label'); }
function render_stored_label(){ echo htmlspecialchars_decode(stored_label()); }
""", set(), ["xss"]),

    ("return summary joins optional clean branch", """<?php
function maybe_clean($value, $condition){
  if ($condition) { $value='fixed'; }
  return $value;
}
function render_maybe_clean(){ echo maybe_clean($_GET['html'], random_int(0,1)); }
""", {"xss"}, []),

    ("return summary ignores unreachable tainted return", """<?php
function always_clean($value, $condition){
  if ($condition) { return 'a'; } else { return 'b'; }
  return $value;
}
function render_always_clean(){ echo always_clean($_GET['html'], random_int(0,1)); }
""", set(), ["xss"]),

    ("SQL helper sanitizer does not clean XSS", """<?php
function sql_only($value){ return esc_sql($value); }
function render(){ echo sql_only($_GET['html']); }
""", {"xss"}, []),

    ("SQL helper sanitizer remains safe for SQL", """<?php
function sql_only($value){ return esc_sql($value); }
function query(){ global $wpdb; $wpdb->query(sql_only($_GET['q'])); }
""", set(), ["sqli"]),

    ("assigned wrong-context sanitizer preserves SQL taint", """<?php
function a(){ global $wpdb; $q=esc_html($_GET['q']); $wpdb->query($q); }
""", {"sqli"}, []),

    ("nested sanitizer in concatenation preserves only unsafe class", """<?php
function a(){
  global $wpdb;
  $where = " WHERE title='" . sanitize_text_field($_GET['q']) . "'";
  echo $where;
  $wpdb->get_results("SELECT * FROM posts" . $where);
}
""", {"sqli"}, []),

    ("augmented concat preserves class-specific taint", """<?php
function a(){
  global $wpdb;
  $where = '';
  $where .= " AND title='" . sanitize_text_field($_GET['q']) . "'";
  $wpdb->get_results("SELECT * FROM posts" . $where);
}
""", {"sqli"}, []),

    ("assigned right-context sanitizer remains SILENT", """<?php
function a(){ $x=esc_html($_GET['x']); echo $x; }
function b(){ global $wpdb; $q=esc_sql($_GET['q']); $wpdb->query($q); }
""", set(), ["xss", "sqli"]),

    ("HTML decoder invalidates prior XSS escaping", """<?php
function decoded(){ $x=esc_html($_GET['x']); $x=htmlspecialchars_decode($x); echo $x; }
""", {"xss"}, []),

    ("branch join cannot hide an unsanitized path", """<?php
function a(){
  $x=esc_html($_GET['x']);
  if (random_int(0,1)) { $x=$_GET['x']; }
  echo $x;
}
""", {"xss"}, []),

    ("exhaustive clean branches clear incoming taint", """<?php
function clean_both(){
  $x=$_GET['x'];
  if (random_int(0,1)) { $x=esc_html($x); } else { $x='fixed'; }
  echo $x;
}
""", set(), ["xss"]),

    ("nested conditional return is not unconditional", """<?php
function nested_return(){
  $x='fixed';
  if (random_int(0,1)) {
    $x=$_GET['x'];
    if (random_int(0,1)) { return; }
  }
  echo $x;
}
""", {"xss"}, []),

    ("terminating branch is excluded from continuation join", """<?php
function one_continuation(){
  $x=$_GET['x'];
  if (random_int(0,1)) { return; } else { $x=esc_html($x); }
  echo $x;
}
""", set(), ["xss"]),

    ("unreachable statement after return does not revive branch", """<?php
function return_then_dead_code(){
  $x=$_GET['x'];
  if (random_int(0,1)) { return; echo $x; } else { $x=esc_html($x); }
  echo $x;
}
""", set(), ["xss"]),

    ("code after exhaustive terminating branches is unreachable", """<?php
function no_continuation(){
  if (random_int(0,1)) { return; } else { throw new Exception('stop'); }
  echo $_GET['x'];
}
""", set(), ["xss"]),

    ("colon exhaustive if makes following sink unreachable", """<?php
function colon_no_continuation($condition){
  if ($condition):
    return;
  else:
    throw new Exception('stop');
  endif;
  echo $_GET['x'];
}
""", set(), ["xss"]),

    ("colon nonterminating consequence remains reachable", """<?php
function colon_has_continuation($condition){
  if ($condition):
    $value='fixed';
  else:
    return;
  endif;
  echo $_GET['x'];
}
""", {"xss"}, []),

    ("elseif condition side effect reaches final else", """<?php
function elseif_condition(){
  $x='fixed';
  if (random_int(0,1)) { }
  elseif (($x=$_GET['x']) && false) { }
  else { echo $x; }
}
""", {"xss"}, []),

    ("single-statement if branches join correctly", """<?php
function unbraced_clean(){
  $x=$_GET['x'];
  if (random_int(0,1)) $x=esc_html($x); else $x='fixed';
  echo $x;
}
""", set(), ["xss"]),

    ("foreach preserves right-context sanitizer annotation", """<?php
function a(){
  $items=array(esc_html($_GET['x']));
  foreach($items as $item){ echo $item; }
}
""", set(), ["xss"]),

    ("CSRF + auth: unguarded state change", """<?php
function save(){ $v=$_POST['opt']; update_option('k',$v); }
""", {"csrf", "auth"}, []),

    ("guarded state change is SILENT", """<?php
function save2(){ if(!current_user_can('manage_options')) return; check_admin_referer('x'); update_option('k',$_POST['opt']); }
""", set(), ["csrf", "auth"]),

    ("open redirect -> other", """<?php
function go(){ wp_redirect($_GET['url']); }
""", {"other"}, []),

    ("SQLi via custom DB-handle wrapper ($this->db->get_col)", """<?php
class C { function q(){ $id=$_GET['id']; $this->db->get_col("SELECT id FROM t WHERE x=".$id); } }
""", {"sqli"}, []),

    ("XSS via object property within method", """<?php
class C { function r(){ $this->raw=$_GET['name']; echo $this->raw; } }
""", {"xss"}, []),

    ("sanitized property is SILENT", """<?php
class C { function s(){ global $wpdb; $this->id=(int)$_GET['id']; $wpdb->query("SELECT * FROM t WHERE id=".$this->id); } }
""", set(), ["sqli"]),

    ("object-injection risk: unserialize(non-literal)", """<?php
function oi($x){ return unserialize($x); }
""", {"deserial"}, []),

    ("unserialize allowed_classes=>false is SILENT", """<?php
function safe_oi($x){ return unserialize($x, ['allowed_classes'=>false]); }
""", set(), ["deserial"]),

    ("REST handler missing capability -> auth (NOT csrf: REST has nonce infra)", """<?php
class R { function update($request){ $v=$request->get_param('v'); update_option('k',$v); } }
""", {"auth"}, ["csrf"]),

    ("REST handler with current_user_can is SILENT", """<?php
class R2 { function upd($request){ if(!current_user_can('manage_options')) return; $v=$request->get_param('v'); update_option('k',$v); } }
""", set(), ["auth", "csrf"]),

    ("REST input reaches sink -> XSS (WP_REST_Request->get_param is a taint source)", """<?php
class R3 { function out($request){ echo $request->get_param('html'); } }
""", {"xss"}, []),

    ("REST callback array seeds direct request access", """<?php
register_rest_route('demo/v1', '/out', [
  'callback' => ['Rest_Handler', 'handle'],
  'permission_callback' => '__return_true'
]);
class Rest_Handler { function handle($request){ echo $request['html']; } }
""", {"xss"}, []),

    ("shortcode callback array renders returned HTML", """<?php
add_shortcode('demo_card', ['Card_Shortcode', 'render']);
class Card_Shortcode {
  function render($atts){ return '<div class="card">'.$atts['html'].'</div>'; }
}
""", {"xss"}, []),

    ("dynamic block render callback returns attribute HTML", """<?php
register_block_type('demo/card', [
  'render_callback' => 'render_card'
]);
function render_card($attributes){ return sprintf('<%s>ok</%s>', $attributes['tag'], $attributes['tag']); }
""", {"xss"}, []),

    ("this-bound block callback resolves its owning class", """<?php
class Owned_Block {
  function setup(){
    register_block_type('demo/owned', ['render_callback' => [$this, 'render']]);
  }
  function render($attributes){ return '<div>'.$attributes['html'].'</div>'; }
}
""", {"xss"}, []),

    ("this-bound callback resolves inherited implementation", """<?php
class Parent_Block_Renderer {
  function render($attributes){ return $attributes['html']; }
}
class Child_Block_Renderer extends Parent_Block_Renderer {
  function setup(){
    register_block_type('demo/inherited', ['render_callback'=>[$this,'render']]);
  }
}
""", {"xss"}, []),

    ("escaped dynamic block return is SILENT", """<?php
register_block_type_from_metadata(__DIR__, [
  'render_callback' => 'render_safe_card'
]);
function render_safe_card($attributes){ return '<div>'.esc_html($attributes['text']).'</div>'; }
""", set(), ["xss"]),

    ("sanitized callback parameter reassignment is SILENT", """<?php
register_block_type('demo/sanitized-param', ['render_callback' => 'render_sanitized_param']);
function render_sanitized_param($attributes){
  $attributes=esc_html($attributes['html']);
  return $attributes;
}
""", set(), ["xss"]),

    ("clean overwrite before render return is SILENT", """<?php
register_block_type('demo/overwritten', ['render_callback' => 'render_overwritten']);
function render_overwritten($attributes){
  $output='<div>'.$attributes['html'].'</div>';
  $output='<div>fixed</div>';
  return $output;
}
""", set(), ["xss"]),

    ("terminated tainted branch cannot leak into later return", """<?php
register_block_type('demo/terminated', ['render_callback' => 'render_terminated']);
function render_terminated($attributes){
  if (random_int(0,1)) {
    $output=$attributes['html'];
    return esc_html($output);
  } else {
    $output='fixed';
  }
  return $output;
}
""", set(), ["xss"]),

    ("elseif overwrite cannot erase prior render candidate", """<?php
register_block_type('demo/elseif-candidate', ['render_callback' => 'render_elseif_candidate']);
function render_elseif_candidate($attributes){
  $output='<div>'.$attributes['html'].'</div>';
  if (random_int(0,1)) { }
  elseif (($output='fixed')) { }
  return $output;
}
""", {"xss"}, []),

    ("zero-iteration loop cannot erase prior render taint", """<?php
register_block_type('demo/loop', ['render_callback' => 'render_loop']);
function render_loop($attributes){
  $output=$attributes['html'];
  foreach (array() as $unused) { $output='fixed'; }
  return $output;
}
""", {"xss"}, []),

    ("do body executes at least once", """<?php
function do_once(){
  $value=$_GET['x'];
  do { $value=esc_html($value); } while(false);
  echo $value;
}
""", set(), ["xss"]),

    ("while condition effects execute at least once", """<?php
function while_condition_once(){
  $value=$_GET['x'];
  while (($value=esc_html($value)) && false) { }
  echo $value;
}
""", set(), ["xss"]),

    ("numeric cast callback return is SILENT", """<?php
add_shortcode('demo_number', 'render_number');
function render_number($atts){ return (int)$atts['count']; }
""", set(), ["xss"]),

    ("safe array element cannot erase earlier raw render element", """<?php
register_block_type('demo/list', ['render_callback' => 'render_list']);
function render_list($attributes){
  $output=array();
  $output[]=$attributes['raw'];
  $output[]=esc_html($attributes['safe']);
  return implode('', $output);
}
""", {"xss"}, []),

    ("ordinary helper return is not an HTML sink", """<?php
function ordinary_helper($value){ return '<div>'.$value.'</div>'; }
""", set(), ["xss"]),

    ("opaque callback helper does not invent rendered taint", """<?php
add_shortcode('protected_post', 'render_protected_post');
function render_protected_post($atts){
  return get_the_password_form(get_post($atts['id']));
}
""", set(), ["xss"]),

    ("opaque callback helper stays opaque through aliases", """<?php
add_shortcode('protected_alias', 'render_protected_alias');
function render_protected_alias($atts){
  $tmp=get_the_password_form(get_post($atts['id']));
  $out=$tmp;
  return $out;
}
""", set(), ["xss"]),

    ("proven callback taint propagates through aliases", """<?php
add_shortcode('raw_alias', 'render_raw_alias');
function render_raw_alias($atts){
  $tmp=$atts['html'];
  $out=$tmp;
  return $out;
}
""", {"xss"}, []),

    ("branch overwrite drops stale render composition", """<?php
register_block_type('demo/path-candidate', ['render_callback'=>'render_path_candidate']);
function render_path_candidate($attributes){
  if (random_int(0,1)) {
    $out='<div>'.$attributes['stale'].'</div>';
    $out='fixed';
  } else {
    $out='<div>'.$attributes['real'].'</div>';
  }
  return $out;
}
""", {"xss"}, []),

    ("filter context argument does not taint returned HTML", """<?php
register_block_type('demo/filtered', ['render_callback' => 'render_filtered']);
function render_filtered($attributes){
  return apply_filters('demo_rendered_html', '', $attributes);
}
""", set(), ["xss"]),

    ("filter value argument preserves rendered taint", """<?php
add_shortcode('demo_filtered_value', 'render_filtered_value');
function render_filtered_value($atts){
  return apply_filters('demo_rendered_html', $atts['html'], 'context-only');
}
""", {"xss"}, []),

    ("commented registration does not seed callback input", """<?php
/* add_shortcode('documentation_example', 'not_registered'); */
function not_registered($atts){ return '<div>'.$atts['html'].'</div>'; }
""", set(), ["xss"]),

    ("commented array key does not seed callback input", """<?php
register_block_type('demo/commented-key', [
  /* 'render_callback' => 'ghost_key_render', */
  'title' => 'No callback'
]);
function ghost_key_render($attributes){ return $attributes['html']; }
""", set(), ["xss"]),

    ("member call named like core registration is SILENT", """<?php
$fake->register_block_type('demo/fake', ['render_callback' => 'fake_render']);
function fake_render($attributes){ return '<div>'.$attributes['html'].'</div>'; }
""", set(), ["xss"]),

    ("namespace-local registration shadow is SILENT", """<?php
namespace Local;
function register_block_type($name, $options){}
register_block_type('demo/local-shadow', ['render_callback'=>'Local\\render']);
function render($attributes){ return $attributes['html']; }
""", set(), ["xss"]),

    ("vendor-qualified registration lookalike is SILENT", """<?php
namespace Local;
Vendor\\register_block_type(
  'demo/vendor-shadow', ['render_callback'=>'Local\\render']
);
function render($attributes){ return $attributes['html']; }
""", set(), ["xss"]),

    ("external callback class cannot seed unrelated local method", """<?php
register_block_type('demo/external', [
  'render_callback' => [External_Handler::class, 'render']
]);
class Other_Handler {
  function render($attributes){ return '<div>'.$attributes['html'].'</div>'; }
}
""", set(), ["xss"]),

    ("external namespaced callback cannot collide by short class name", """<?php
namespace LocalPlugin;
register_block_type('demo/external-fq', [
  'render_callback' => [\Vendor\Package\Handler::class, 'render']
]);
class Handler {
  function render($attributes){ return '<div>'.$attributes['html'].'</div>'; }
}
""", set(), ["xss"]),

    ("FQ class-constant callback resolves namespaced method", """<?php
namespace My;
\\register_block_type('demo/fq-class', [
  'render_callback' => [\\My\\Handler::class, 'render']
]);
class Handler { function render($attributes){ return $attributes['html']; } }
""", {"xss"}, []),

    ("FQ string callback resolves namespaced method", """<?php
namespace My;
\\register_block_type('demo/fq-string', [
  'render_callback' => 'My\\Handler::render'
]);
class Handler { function render($attributes){ return $attributes['html']; } }
""", {"xss"}, []),

    ("FQ free callback cannot seed unrelated short function", """<?php
namespace Local;
\\register_block_type('demo/external-free', [
  'render_callback' => 'My\\render'
]);
function render($attributes){ return $attributes['html']; }
""", set(), ["xss"]),

    ("FQ free callback resolves exact namespaced function", """<?php
namespace My { function render($attributes){ return $attributes['html']; } }
namespace Boot {
  \\register_block_type('demo/exact-free', ['render_callback' => 'My\\render']);
}
""", {"xss"}, []),

    ("explicit callback class disambiguates same-named methods", """<?php
register_block_type('demo/classed', ['render_callback' => [Safe_Block::class, 'render']]);
class Safe_Block { function render($attributes){ return '<div>fixed</div>'; } }
class Unrelated_Block {
  function render($attributes){ return '<div>'.$attributes['html'].'</div>'; }
}
""", set(), ["xss"]),

    ("embed callback URL reaches SSRF sink", """<?php
wp_embed_register_handler('demo', '#https?://example.test/(.*)#i', 'fetch_embed');
function fetch_embed($matches, $attr, $url, $rawattr){
  return wp_remote_get($url);
}
""", {"ssrf"}, []),

    ("singleton-factory embed callback reaches SSRF sink", """<?php
wp_embed_register_handler('demo', '#https?://example.test/(.*)#i',
  [Embed_Factory::instance(), 'fetch_embed']);
class Embed_Factory {
  static function instance(){ return new self; }
  function fetch_embed($matches, $attr, $url, $rawattr){
    return wp_remote_get($url);
  }
}
""", {"ssrf"}, []),

    ("safe remote API is not an SSRF sink", """<?php
wp_embed_register_handler('safe', '#https?://example.test/(.*)#i', 'fetch_safe');
function fetch_safe($matches, $attr, $url, $rawattr){
  return wp_safe_remote_get($url);
}
""", set(), ["ssrf"]),

    ("ACF stored choice label reaches rendered field", """<?php
class Demo_ACF_Field extends \\acf_field {
  function render_field($field){
    $value=$field['value'];
    $decoded=json_decode($value);
    $field['choices'][$value]=$decoded->label;
    acf_render_field($field);
  }
}
""", {"xss"}, []),

    ("escaped ACF choice label remains SILENT", """<?php
class Safe_ACF_Field extends \\acf_field {
  function render_field($field){
    $value=$field['value'];
    $decoded=json_decode($value);
    $field['choices'][$value]=esc_html($decoded->label);
    acf_render_field($field);
  }
}
""", set(), ["xss"]),

    ("inter-procedural summary retains every sink class", """<?php
function both($value){ global $wpdb; echo $value; $wpdb->query($value); }
function route(){ both($_GET['value']); }
""", {"xss", "sqli"}, []),

    ("summary fixpoint reaches deep reverse-ordered chain", """<?php
function sinker($x){ echo $x; }
function w4($x){ sinker($x); }
function w3($x){ w4($x); }
function w2($x){ w3($x); }
function w1($x){ w2($x); }
function run_deep(){ w1($_GET['x']); }
""", {"xss"}, []),

    ("child resolves inherited sink", """<?php
class Parent_Sink { function sink($x){ echo $x; } }
class Child_Sink extends Parent_Sink {
  function run(){ $this->sink($_GET['x']); }
}
""", {"xss"}, []),

    ("child resolves inherited sanitizer", """<?php
class Parent_Safe { function safe($x){ return esc_html($x); } }
class Child_Safe extends Parent_Safe {
  function run(){ echo $this->safe($_GET['x']); }
}
""", set(), ["xss"]),

    ("virtual dispatch includes unsafe override", """<?php
class Dispatch_Base {
  function safe($x){ return esc_html($x); }
  function run(){ echo $this->safe($_GET['x']); }
}
class Dispatch_Child extends Dispatch_Base {
  function safe($x){ return $x; }
}
""", {"xss"}, []),

    ("inline new receiver resolves method sink", """<?php
class Inline_Receiver { function sink($x){ echo $x; } }
function run_inline(){ (new Inline_Receiver)->sink($_GET['x']); }
""", {"xss"}, []),

    ("assigned new receiver resolves method sink", """<?php
class Assigned_Receiver { function sink($x){ echo $x; } }
function run_assigned(){
  $receiver = new Assigned_Receiver;
  $receiver->sink($_GET['x']);
}
""", {"xss"}, []),

    ("typed receiver resolves method sink", """<?php
class Typed_Receiver { function sink($x){ echo $x; } }
function run_typed(Typed_Receiver $receiver){
  $receiver->sink($_GET['x']);
}
""", {"xss"}, []),
]


def run():
    failures = []
    for label, php, expect, silent in CASES:
        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as fh:
            fh.write(php)
            path = fh.name
        try:
            findings, _ = te.detect_file(path, os.path.basename(path), {})
        finally:
            os.unlink(path)
        classes = {f.vuln_class for f in findings}
        missing = expect - classes
        leaked = [s for s in silent if s in classes]
        status = "PASS"
        if missing or leaked:
            status = "FAIL"
            failures.append((label, missing, leaked))
        print(f"  [{status}] {label}"
              f"{'  MISSING=' + str(sorted(missing)) if missing else ''}"
              f"{'  FALSE-POSITIVE=' + str(leaked) if leaked else ''}")

    # plugin-level case: cross-method object-property taint (needs detect(), which
    # builds the plugin-wide TAINTED_PROPS summary). A property set from request in
    # one method and sunk in another must be connected.
    import types
    d = tempfile.mkdtemp()
    fp = os.path.join(d, "x.php")
    with open(fp, "w") as fh:
        fh.write("<?php\nclass C { function set(){ $this->cb=$_POST['fn']; } "
                 "function run(){ call_user_func($this->cb); } }\n")
    plug = types.SimpleNamespace(php_files=[fp], root=d, slug="t", cleanup=lambda: None)
    cm_classes = {f.vuln_class for f in te.detect(plug)}
    os.unlink(fp)
    if "rce" in cm_classes:
        print("  [PASS] cross-method object-property RCE (plugin-level)")
    else:
        print("  [FAIL] cross-method object-property RCE (plugin-level)  MISSING=['rce']")
        failures.append(("cross-method property RCE", {"rce"}, []))

    top_prop_path = os.path.join(d, "top_prop.php")
    with open(top_prop_path, "w") as fh:
        fh.write("<?php\n$singleton->raw=$_GET['html'];\n"
                 "function render_top_prop(){ global $singleton; echo $singleton->raw; }\n")
    top_prop_plugin = types.SimpleNamespace(
        php_files=[top_prop_path], root=d, slug="top-prop", cleanup=lambda: None)
    top_prop_classes = {f.vuln_class for f in te.detect(top_prop_plugin)}
    if "xss" in top_prop_classes:
        print("  [PASS] top-level assignment propagates through object property")
    else:
        print("  [FAIL] top-level property propagation  MISSING=['xss']")
        failures.append(("top-level property XSS", {"xss"}, []))
    os.unlink(top_prop_path)

    prop_summary_path = os.path.join(d, "prop_summary.php")
    with open(prop_summary_path, "w") as fh:
        fh.write("""<?php
class Property_Chain {
  function seed(){ $this->raw=$_GET['html']; }
  function get(){ return $this->raw; }
  function copy(){ $this->copy=$this->get(); }
  function out(){ echo $this->copy; }
}
""")
    prop_summary_plugin = types.SimpleNamespace(
        php_files=[prop_summary_path], root=d, slug="prop-summary", cleanup=lambda: None)
    prop_summary_classes = {f.vuln_class for f in te.detect(prop_summary_plugin)}
    if "xss" in prop_summary_classes:
        print("  [PASS] property and return summaries reach a joint fixpoint")
    else:
        print("  [FAIL] property/summary fixpoint  MISSING=['xss']")
        failures.append(("property/summary fixpoint", {"xss"}, []))
    os.unlink(prop_summary_path)

    setter_prop_path = os.path.join(d, "setter_prop.php")
    with open(setter_prop_path, "w") as fh:
        fh.write("""<?php
class Setter_Property_Flow {
  function set_raw($value){ $this->raw=$value; }
  function forward($value){ $this->set_raw($value); }
  function seed(){ $this->forward($_GET['html']); }
  function out(){ echo $this->raw; }
}
""")
    setter_prop_plugin = types.SimpleNamespace(
        php_files=[setter_prop_path], root=d, slug="setter-prop", cleanup=lambda: None)
    setter_prop_classes = {f.vuln_class for f in te.detect(setter_prop_plugin)}
    if "xss" in setter_prop_classes:
        print("  [PASS] transitive setter parameter reaches object property")
    else:
        print("  [FAIL] setter parameter/property flow  MISSING=['xss']")
        failures.append(("setter parameter property", {"xss"}, []))
    os.unlink(setter_prop_path)

    safe_setter_path = os.path.join(d, "safe_setter_prop.php")
    with open(safe_setter_path, "w") as fh:
        fh.write("""<?php
class Safe_Setter_Property {
  function set_raw($value){ $this->raw=esc_html($value); }
  function seed(){ $this->set_raw($_GET['html']); }
  function out(){ echo $this->raw; }
}
""")
    safe_setter_plugin = types.SimpleNamespace(
        php_files=[safe_setter_path], root=d, slug="safe-setter", cleanup=lambda: None)
    safe_setter_classes = {f.vuln_class for f in te.detect(safe_setter_plugin)}
    if "xss" not in safe_setter_classes:
        print("  [PASS] setter sanitizer remains attached to property effect")
    else:
        print("  [FAIL] setter sanitizer property effect  FALSE-POSITIVE=['xss']")
        failures.append(("safe setter property", set(), ["xss"]))
    os.unlink(safe_setter_path)

    # Framework-controlled callback input can be stored on an object and rendered
    # by a helper method. Property propagation must retain both the flow and the
    # sanitizer class attached at the write.
    callback_prop_path = os.path.join(d, "callback_prop.php")
    with open(callback_prop_path, "w") as fh:
        fh.write("""<?php
class Callback_Block {
  function setup(){ register_block_type('demo/prop', ['render_callback'=>[$this,'render']]); }
  function render($attributes){ $this->tag=$attributes['tag']; return $this->html(); }
  function html(){ return '<'.$this->tag.'>'; }
}
""")
    callback_plugin = types.SimpleNamespace(
        php_files=[callback_prop_path], root=d, slug="callback-prop", cleanup=lambda: None)
    callback_prop_classes = {f.vuln_class for f in te.detect(callback_plugin)}
    if "xss" in callback_prop_classes:
        print("  [PASS] callback input propagates through object property")
    else:
        print("  [FAIL] callback input propagates through object property  MISSING=['xss']")
        failures.append(("callback property XSS", {"xss"}, []))
    os.unlink(callback_prop_path)

    safe_prop_path = os.path.join(d, "safe_callback_prop.php")
    with open(safe_prop_path, "w") as fh:
        fh.write("""<?php
class Safe_Callback_Block {
  function setup(){ register_block_type('demo/safe-prop', ['render_callback'=>[$this,'render']]); }
  function render($attributes){ $this->tag=esc_html($attributes['tag']); return $this->html(); }
  function html(){ return '<'.$this->tag.'>'; }
}
""")
    safe_plugin = types.SimpleNamespace(
        php_files=[safe_prop_path], root=d, slug="safe-prop", cleanup=lambda: None)
    safe_prop_classes = {f.vuln_class for f in te.detect(safe_plugin)}
    if "xss" not in safe_prop_classes:
        print("  [PASS] sanitized callback property remains SILENT")
    else:
        print("  [FAIL] sanitized callback property remains SILENT  FALSE-POSITIVE=['xss']")
        failures.append(("sanitized callback property", set(), ["xss"]))
    os.unlink(safe_prop_path)

    case_prop_path = os.path.join(d, "case_sensitive_prop.php")
    with open(case_prop_path, "w") as fh:
        fh.write("""<?php
class Case_Sensitive_Property {
  function set(){ $this->Raw=$_GET['html']; }
  function out(){ echo $this->raw; }
}
""")
    case_prop_plugin = types.SimpleNamespace(
        php_files=[case_prop_path], root=d, slug="case-prop", cleanup=lambda: None)
    case_prop_classes = {f.vuln_class for f in te.detect(case_prop_plugin)}
    if "xss" not in case_prop_classes:
        print("  [PASS] PHP property-name case remains distinct")
    else:
        print("  [FAIL] PHP property-name case remains distinct  FALSE-POSITIVE=['xss']")
        failures.append(("case-sensitive property", set(), ["xss"]))
    os.unlink(case_prop_path)

    static_prop_path = os.path.join(d, "static_prop.php")
    with open(static_prop_path, "w") as fh:
        fh.write("""<?php
class Static_Property_Flow {
  static $raw;
  function set(){ self::$raw=$_GET['html']; }
  function out(){ echo static::$raw; echo Static_Property_Flow::$raw; }
}
""")
    static_prop_plugin = types.SimpleNamespace(
        php_files=[static_prop_path], root=d, slug="static-prop", cleanup=lambda: None)
    static_prop_classes = {f.vuln_class for f in te.detect(static_prop_plugin)}
    if "xss" in static_prop_classes:
        print("  [PASS] equivalent static-property forms share one key")
    else:
        print("  [FAIL] equivalent static-property forms  MISSING=['xss']")
        failures.append(("static property normalization", {"xss"}, []))
    os.unlink(static_prop_path)

    # Preserve both ends of a cross-file flow: file/line stays at the callsite for
    # backward-compatible triage, while sink_file/sink_line identifies the ultimate
    # operation for trace-aware defect correspondence.
    sink_path = os.path.join(d, "sink.php")
    caller_path = os.path.join(d, "caller.php")
    with open(sink_path, "w") as fh:
        fh.write("<?php\nfunction render_untrusted($value){ echo $value; }\n")
    with open(caller_path, "w") as fh:
        fh.write("<?php\nfunction route(){ render_untrusted($_GET['value']); }\n")
    plug2 = types.SimpleNamespace(
        php_files=[sink_path, caller_path], root=d, slug="location", cleanup=lambda: None)
    located = [f for f in te.detect(plug2) if f.vuln_class == "xss"]
    if (located and located[0].file == "caller.php" and located[0].line == 2
            and located[0].sink_file == "sink.php" and located[0].sink_line == 2):
        print("  [PASS] inter-procedural finding retains callsite and ultimate sink")
    else:
        got = [(f.file, f.line, f.sink_file, f.sink_line) for f in located]
        print(f"  [FAIL] inter-procedural finding retains both locations  GOT={got}")
        failures.append(("inter-procedural locations",
                         {"caller.php:2 -> sink.php:2"}, got))

    with open(sink_path, "w") as fh:
        fh.write("<?php\nfunction render_twice($value){\n echo $value;\n echo $value;\n}\n")
    with open(caller_path, "w") as fh:
        fh.write("<?php\nfunction route_twice(){ render_twice($_GET['value']); }\n")
    plug3 = types.SimpleNamespace(
        php_files=[sink_path, caller_path], root=d, slug="multi-location",
        cleanup=lambda: None)
    endpoint_lines = {
        f.sink_line for f in te.detect(plug3)
        if f.vuln_class == "xss" and f.interprocedural and f.sink_file == "sink.php"
    }
    if {3, 4}.issubset(endpoint_lines):
        print("  [PASS] same-class multi-sink endpoints survive deduplication")
    else:
        print(f"  [FAIL] same-class multi-sink endpoints  GOT={sorted(endpoint_lines)}")
        failures.append(("multi-sink endpoint dedupe", {3, 4}, endpoint_lines))
    os.unlink(sink_path)
    os.unlink(caller_path)
    os.rmdir(d)
    print()
    if failures:
        print(f"REGRESSION: {len(failures)} case(s) failed")
        return 1
    print(f"ALL {len(CASES) + 11} CASES PASS")
    return 0


if __name__ == "__main__":
    sys.exit(run())
