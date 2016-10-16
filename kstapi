--KristAPI Alpha
local version = "Alpha 0.62"
if not http then
  printError("KristAPI " .. version .. " requires the HTTP API to be enabled!")
  failedLoad = true
  return
end
function getVersion()
  return version
end
local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end
base = trim(http.get("https://raw.githubusercontent.com/BTCTaras/kristwallet/master/staticapi/syncNode").readAll())
--SHA256, needed for other processes
local MOD = 2^32
local MODM = MOD-1
local function memoize(f)
        local mt = {}
        local t = setmetatable({}, mt)
        function mt:__index(k)
                local v = f(k)
                t[k] = v
                return v
        end
        return t
end
local function make_bitop_uncached(t, m)
        local function bitop(a, b)
                local res,p = 0,1
                while a ~= 0 and b ~= 0 do
                        local am, bm = a % m, b % m
                        res = res + t[am][bm] * p
                        a = (a - am) / m
                        b = (b - bm) / m
                        p = p*m
                end
                res = res + (a + b) * p
                return res
        end
        return bitop
end
local function make_bitop(t)
        local op1 = make_bitop_uncached(t,2^1)
        local op2 = memoize(function(a) return memoize(function(b) return op1(a, b) end) end)
        return make_bitop_uncached(op2, 2 ^ (t.n or 1))
end
local bxor1 = make_bitop({[0] = {[0] = 0,[1] = 1}, [1] = {[0] = 1, [1] = 0}, n = 4})
local function bxor(a, b, c, ...)
        local z = nil
        if b then
                a = a % MOD
                b = b % MOD
                z = bxor1(a, b)
                if c then z = bxor(z, c, ...) end
                return z
        elseif a then return a % MOD
        else return 0 end
end
local function band(a, b, c, ...)
        local z
        if b then
                a = a % MOD
                b = b % MOD
                z = ((a + b) - bxor1(a,b)) / 2
                if c then z = bit32_band(z, c, ...) end
                return z
        elseif a then return a % MOD
        else return MODM end
end
local function bnot(x) return (-1 - x) % MOD end
local function rshift1(a, disp)
        if disp < 0 then return lshift(a,-disp) end
        return math.floor(a % 2 ^ 32 / 2 ^ disp)
end
local function rshift(x, disp)
        if disp > 31 or disp < -31 then return 0 end
        return rshift1(x % MOD, disp)
end
local function lshift(a, disp)
        if disp < 0 then return rshift(a,-disp) end
        return (a * 2 ^ disp) % 2 ^ 32
end
local function rrotate(x, disp)
    x = x % MOD
    disp = disp % 32
    local low = band(x, 2 ^ disp - 1)
    return rshift(x, disp) + lshift(low, 32 - disp)
end
local k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
local function str2hexa(s)
        return (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end
local function num2s(l, n)
        local s = ""
        for i = 1, n do
                local rem = l % 256
                s = string.char(rem) .. s
                l = (l - rem) / 256
        end
        return s
end
local function s232num(s, i)
        local n = 0
        for i = i, i + 3 do n = n*256 + string.byte(s, i) end
        return n
end
local function preproc(msg, len)
        local extra = 64 - ((len + 9) % 64)
        len = num2s(8 * len, 8)
        msg = msg .. "\128" .. string.rep("\0", extra) .. len
        assert(#msg % 64 == 0)
        return msg
end
local function initH256(H)
        H[1] = 0x6a09e667
        H[2] = 0xbb67ae85
        H[3] = 0x3c6ef372
        H[4] = 0xa54ff53a
        H[5] = 0x510e527f
        H[6] = 0x9b05688c
        H[7] = 0x1f83d9ab
        H[8] = 0x5be0cd19
        return H
end
local function digestblock(msg, i, H)
        local w = {}
        for j = 1, 16 do w[j] = s232num(msg, i + (j - 1)*4) end
        for j = 17, 64 do
                local v = w[j - 15]
                local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
                v = w[j - 2]
                w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(v, 17), rrotate(v, 19), rshift(v, 10))
        end
 
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for i = 1, 64 do
                local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
                local maj = bxor(band(a, b), band(a, c), band(b, c))
                local t2 = s0 + maj
                local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
                local ch = bxor (band(e, f), band(bnot(e), g))
                local t1 = h + s1 + ch + k[i] + w[i]
                h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
        end
 
        H[1] = band(H[1] + a)
        H[2] = band(H[2] + b)
        H[3] = band(H[3] + c)
        H[4] = band(H[4] + d)
        H[5] = band(H[5] + e)
        H[6] = band(H[6] + f)
        H[7] = band(H[7] + g)
        H[8] = band(H[8] + h)
end
function sha256(msg)
        msg = preproc(msg, #msg)
        local H = initH256({})
        for i = 1, #msg, 64 do digestblock(msg, i, H) end
        return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) ..
                num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
end
--Making V2 address. Intended for wallets.
local function tobase36(j)
  if j <= 6 then return "0"
  elseif j <= 13 then return "1"
  elseif j <= 20 then return "2"
  elseif j <= 27 then return "3"
  elseif j <= 34 then return "4"
  elseif j <= 41 then return "5"
  elseif j <= 48 then return "6"
  elseif j <= 55 then return "7"
  elseif j <= 62 then return "8"
  elseif j <= 69 then return "9"
  elseif j <= 76 then return "a"
  elseif j <= 83 then return "b"
  elseif j <= 90 then return "c"
  elseif j <= 97 then return "d"
  elseif j <= 104 then return "e"
  elseif j <= 111 then return "f"
  elseif j <= 118 then return "g"
  elseif j <= 125 then return "h"
  elseif j <= 132 then return "i"
  elseif j <= 139 then return "j"
  elseif j <= 146 then return "k"
  elseif j <= 153 then return "l"
  elseif j <= 160 then return "m"
  elseif j <= 167 then return "n"
  elseif j <= 174 then return "o"
  elseif j <= 181 then return "p"
  elseif j <= 188 then return "q"
  elseif j <= 195 then return "r"
  elseif j <= 202 then return "s"
  elseif j <= 209 then return "t"
  elseif j <= 216 then return "u"
  elseif j <= 223 then return "v"
  elseif j <= 230 then return "w"
  elseif j <= 237 then return "x"
  elseif j <= 244 then return "y"
  elseif j <= 251 then return "z"
  else return "e" --e is most commonly sought for vanity addresses
  end
end
function makev2address(key)
  local protein = {}
  local stick = sha256(sha256(key))
  local n = 0
  local link = 0
  local v2 = "k"
  repeat
    if n < 9 then protein[n] = string.sub(stick,0,2)
    stick = sha256(sha256(stick)) end
    n = n + 1
  until n == 9
  n = 0
  repeat
    link = tonumber(string.sub(stick,1+(2*n),2+(2*n)),16) % 9
    if string.len(protein[link]) ~= 0 then
      v2 = v2 .. tobase36(tonumber(protein[link],16))
      protein[link] = ''
      n = n + 1
    else
      stick = sha256(stick)
    end
  until n == 9
  return v2
end
--used for some other functions
local function explode(div,str) -- credit: http://richard.warburton.it
  if (div=='') then return false end
  local pos,arr = 0,{}
  -- for each divider found
  for st,sp in function() return string.find(str,div,pos,true) end do
    table.insert(arr,string.sub(str,pos,st-1)) -- Attach chars left of current divider
    pos = sp + 1 -- Jump past current divider
  end
  table.insert(arr,string.sub(str,pos)) -- Attach chars right of last divider
  return arr
end
--Create address with password.
function createaddress(password)
  return makev2address(sha256("KRISTWALLET" .. password) .. "-000")
end
--Create an outdated V1 address with password.
function createv1address(password)
  local txt = sha256("KRISTWALLET" .. password) .. "-000"
  return txt:sub(0, 10)
end
--Create a double vault. Returns the key and password of the vault (password is for use in all other functions, for give() set the fourth parameter to true)
function createvault(password1, password2) --password1 = vault password, password2 = your password
  masterkey = sha256("KRISTWALLET" .. password2) .. "-000"
  pass = sha256(masterkey .. "-"..sha256(password1))
  address = makev2address(pass)
  return address, pass
end
--There is no local vault function, as it is literally just a sha256 hash stored as a file.
--Allows any amount of passwords in a vault; the last is always your password. Returns the same as above, same syntax as above.
--NOTE: Encodes differently than createvault(), they are not interchangeable!
function createcustomvault(...)
  local tArgs = {...}
  local yp = tArgs[#tArgs]
  local args = {}
  for i = 1, #tArgs-1 do
    args[i] = tArgs[i]
  end
  tArgs = args
  masterkey = sha256("KRISTWALLET" .. yp) .. "-000"
  str = ""
  for i = 1, #tArgs do
    str = str .. sha256(tArgs[i])
  end
  pass = sha256(masterkey .. "-" .. sha256(str))
  address = makev2address(pass)
  return address, pass
end
--Create an outdated V1 address from a raw string (used for first few days of Krist).
function createrawaddress(password)
  local txt = sha256(password)
  return txt:sub(0, 10);
end
--Returns all .kst domains a user has with KristScape. Returns a table like {"atenefyr":"redirect.com"}
function getdomains(address) --address is the user's 10-character string, like "kcyd5vejdw"
  local t = explode(";", http.get(base .. "?listnames=" .. address).readAll())
  t[#t] = nil
  local ta = {}
  for i = 1, #t do
    ta[t[i]] = http.get(base .. "?a=" .. t[i]).readAll()
  end
  return ta
end
--Sending money
function give(to, amount, password, isVault) --Be sure to set "isVault" to true if you're using a sha256 hash!
  if not isVault then
    mkey = sha256("KRISTWALLET" .. password)
  else
    mkey = password
  end
  local trans = http.get(base .. "?pushtx2&q=" .. to .. "&pkey=" .. mkey .. "-000&amt=" .. amount).readAll()
  if trans == "Success" then
      return true
  elseif string.sub(trans, 0,5) == "Error" then
    local prob = "Unknown Error"
	  local c = tonumber(string.sub(trans,6,10))
	  if c == 1 then
	    prob = "Insufficient funds"
	  elseif c == 2 then
	    prob = "Not enough KST"
	  elseif c == 3 then
	    prob = "Not perceived as number"
	  elseif c == 4 then
	    prb = "Invalid receiver"
	  end
	  return false, prb
    else
      printError(trans)
    end
end
--Get balance
function balance(address) --Used with miner address, you can do balance(createaddress(password)) if you want to use the password but it will be slow
  local balance = http.get(base .. "?getbalance=" .. address).readAll()
  return balance
end
--Get value of next block
function blockValue()
  local baseblock = http.get(base .. "?getbaseblockvalue").readAll()
  local addon = http.get(base .. "?getdomainaward").readAll()
  local comb = tonumber(baseblock)+tonumber(addon)
  return comb
end

failedLoad = false
