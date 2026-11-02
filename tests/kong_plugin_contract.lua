-- Execute owned Kong plugin/schema against a mock Kong API; no gateway is run.
local prefix = 'vendor/kong-gateway/plugins/codestra-gateway-identity/'
local headers, status, body = {}, nil, nil
kong = { response = { exit = function(s,b) status,body=s,b; return s end }, service = { request = { set_header = function(k,v) headers[k]=v end } } }
local original = io.open
local plugin = dofile(prefix .. 'handler.lua')
for _, secret in ipairs({'', '   \n'}) do
 io.open = function() return {read=function() return secret end, close=function() end} end
 status=nil; plugin:access({secret_file='/ci-only'})
 assert(status==503 and body.error=='gateway_identity_unavailable')
end
io.open = function() return nil end
status=nil;plugin:access({secret_file='/ci-only'});assert(status==503)
io.open = function() return {read=function() return 'ci-isolated-material\n' end, close=function() end} end
status=nil;plugin:access({secret_file='/ci-only'})
assert(status==nil and headers['X-Codestra-Gateway-Secret']=='ci-isolated-material')
io.open=original
package.preload['kong.db.schema.typedefs'] = function() return {protocols_http={type='set', elements={type='string',one_of={'http','https'}}}} end
local schema=dofile(prefix .. 'schema.lua')
assert(schema.name=='codestra-gateway-identity')
assert(schema.fields[2].config.fields[1].secret_file.required==true)
assert(schema.fields[2].config.fields[1].secret_file.default=='/run/secrets/control_plane_gateway_secret')
print('KONG_PLUGIN_ISOLATED_BEHAVIOR_AND_SCHEMA=PASS')
