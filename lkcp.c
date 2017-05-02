#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#if defined(WIN32) || defined(_WIN32)
# include <windows.h>
#else
# include <sys/time.h>
# include <unistd.h>
#endif /* if defined(WIN32) || defined(_WIN32) */
#include "ikcp.h"

/*
 * #define ENABLE_LKCP_DEBUG
 */
#ifdef ENABLE_LKCP_DEBUG
# define DLOG(fmt, ...) fprintf(stderr, "<lkcp>" fmt "\n", ##__VA_ARGS__)
#else
# define DLOG(...)
#endif

#if LUA_VERSION_NUM < 502
# ifndef luaL_newlib
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
# endif
# ifndef lua_setuservalue
#  define lua_setuservalue(L, n) lua_setfenv(L, n)
# endif
# ifndef lua_getuservalue
#  define lua_getuservalue(L, n) lua_getfenv(L, n)
# endif
#endif

#define LIKCP_PEER_NAME "kcp_cls{peer}"
#define LIKCP_PEER_MAP "kcp_map{peer}"
#define LIKCP_OUTPUT_CB "kcp_output_cb{peer}"

#define LUA_BIND_META(L, type_t, ptr, mname) do {                   \
	type_t **my__p = lua_newuserdata(L, sizeof(void *));        \
	*my__p = ptr;                                               \
	luaL_getmetatable(L, mname);                                \
	lua_setmetatable(L, -2);                                    \
} while(0)

#define CHECK_PEER(L, idx)\
	(*(ikcpcb **) luaL_checkudata(L, idx, LIKCP_PEER_NAME))

#define LUA_SETFIELD(L, index, name, var) 	\
	(lua_pushstring(L, name), 		\
	lua_pushnumber(L, var), 		\
	lua_settable(L, index >= 0 ? index : index - 2))

#define LUA_SET_PEER_STATE(L, idx, name, peer)\
	LUA_SETFIELD(L, idx, #name, peer->name)

#define BUFFER_SIZE (8 * 1024)

#define PEER_FIELD_MAP(XX)                                            \
	XX(conv) XX(mtu) XX(mss) XX(state)                            \
	XX(snd_una) XX(snd_nxt) XX(rcv_nxt)                           \
	XX(ts_recent) XX(ts_lastack) XX(ssthresh)                     \
	XX(rx_rttval) XX(rx_srtt) XX(rx_rto) XX(rx_minrto)            \
	XX(snd_wnd) XX(rcv_wnd) XX(rmt_wnd) XX(cwnd) XX(probe)        \
	XX(current) XX(interval) XX(ts_flush) XX(xmit)                \
	XX(nrcv_buf) XX(nsnd_buf)                                     \
	XX(nrcv_que) XX(nsnd_que)                                     \
	XX(nodelay) XX(updated)                                       \
	XX(ts_probe) XX(probe_wait)                                   \
	XX(dead_link) XX(incr)                                        \
	XX(fastresend)                                                \
	XX(nocwnd)                                                    \
	XX(logmask)

#define LIKCP_LOG_MAP(XX)                                 \
	XX(IKCP_LOG_OUTPUT) XX(IKCP_LOG_INPUT)            \
	XX(IKCP_LOG_SEND) XX(IKCP_LOG_RECV)               \
	XX(IKCP_LOG_IN_DATA) XX(IKCP_LOG_IN_ACK)          \
	XX(IKCP_LOG_IN_PROBE) XX(IKCP_LOG_IN_WINS)        \
	XX(IKCP_LOG_OUT_DATA) XX(IKCP_LOG_OUT_ACK)        \
	XX(IKCP_LOG_OUT_PROBE) XX(IKCP_LOG_OUT_WINS)

static int lua__sleep(lua_State *L)
{
        int ms = (int)luaL_optinteger(L, 1, 0);
#if defined(WIN32) || defined(_WIN32)
        Sleep(ms);
#else
        usleep((useconds_t)ms * 1000);
#endif
        lua_pushboolean(L, 1);
        return 1;
}

static inline void itimeofday(long *sec, long *usec)
{
#if defined(WIN32) || defined(_WIN32)
	static long mode = 0, addsec = 0;
	BOOL retval;
	static IINT64 freq = 1;
	IINT64 qpc;
	if (mode == 0) {
		retval = QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
		freq = (freq == 0)? 1 : freq;
		retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
		addsec = (long)time(NULL);
		addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
		mode = 1;
	}
	retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
	retval = retval * 2;
	if (sec) *sec = (long)(qpc / freq) + addsec;
	if (usec) *usec = (long)((qpc % freq) * 1000000 / freq);
#else
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
#endif
}

static uint64_t iclock64(void)
{
	long s, u;
	uint64_t value;
	itimeofday(&s, &u);
	value = ((uint64_t)s) * 1000 + (u / 1000);
	return value;
}

static uint32_t iclock()
{
	return (uint32_t)(iclock64() & 0xfffffffful);
}


static int output_cb(const char *buf, int len, ikcpcb *peer, void *user)
{
	lua_State * L = user;
	int top;
	int ret = -1;
	lua_Integer ptr = (lua_Integer)peer;
	assert(L != NULL);
	top = lua_gettop(L);
	lua_getfield(L, LUA_REGISTRYINDEX, LIKCP_PEER_MAP);
	lua_pushinteger(L, ptr);
	lua_rawget(L, -2);
	if (lua_type(L, -1) != LUA_TUSERDATA) {
		goto finished;
	}
	lua_getuservalue(L, -1);
	if (!lua_istable(L, -1)) {
		goto finished;
	}
	lua_getfield(L, -1, LIKCP_OUTPUT_CB);
	if (!lua_isfunction(L, -1)) {
		DLOG("output_cb not found")
		goto finished;
	}
	lua_pushvalue(L, -3);
	lua_pushlstring(L, buf, len);
	ret = lua_pcall(L, 2, 0, 0);
finished:
	lua_settop(L, top);
	return ret;
}

static int lua__new(lua_State *L)
{
	lua_Integer ptr;
	IUINT32 conv = (IUINT32)luaL_checknumber(L, 1);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	ikcpcb *peer = ikcp_create(conv, L);
	ptr = (lua_Integer)peer;
	peer->output = output_cb;
	LUA_BIND_META(L, ikcpcb, peer, LIKCP_PEER_NAME);
	lua_newtable(L);
	do {
		lua_pushvalue(L, 2);
		lua_setfield(L, -2, LIKCP_OUTPUT_CB);
	} while(0);
	lua_setuservalue(L, -2);


	lua_getfield(L, LUA_REGISTRYINDEX, LIKCP_PEER_MAP);
	lua_pushinteger(L, ptr);
	lua_pushvalue(L, -3);
	lua_rawset(L, -3);
	lua_pop(L, 1);

	return 1;
}

static int lua__gc(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	lua_Integer ptr = (lua_Integer)peer;

	lua_getfield(L, LUA_REGISTRYINDEX, LIKCP_PEER_MAP);
	lua_pushinteger(L, ptr);
	lua_pushnil(L);
	lua_rawset(L, -3);

	ikcp_release(peer);
	return 0;
}

/* {{ method */
static int lua__recv(lua_State *L)
{
	char buffer[BUFFER_SIZE];
	ikcpcb *peer = CHECK_PEER(L, 1);
	peer->user = L;
	int len = ikcp_recv(peer, buffer, sizeof(buffer));
	if (len >= 0) {
		lua_pushlstring(L, buffer, len);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, "EAGAIN");
	return 2;
}

static int lua__wndsize(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	/* IKCP_WND_SND = 32 */
	int sndwnd = (int)luaL_optinteger(L, 2, 32);
	/* IKCP_WND_RCV = 32 */
	int rcvwnd = (int)luaL_optinteger(L, 3, 32);
	ikcp_wndsize(peer, sndwnd, rcvwnd);
	return 0;
}

static int lua__nodelay(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int nodelay = (int)luaL_optinteger(L, 2, 0);
	/* IKCP_INTERVAL = 100 */
	int interval = (int)luaL_optinteger(L, 3, 100);
	int resend = (int)luaL_optinteger(L, 4, 0);
	int nc = (int)luaL_optinteger(L, 5, 0);
	ikcp_nodelay(peer, nodelay, interval, resend, nc);
	return 0;
}

static int lua__send(lua_State *L)
{
	size_t sz;
	ikcpcb *peer = CHECK_PEER(L, 1);
	const char * buffer = luaL_checklstring(L, 2, &sz);
	peer->user = L;
	ikcp_send(peer, buffer, sz);
	return 0;
}

static int lua__setmtu(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	/* IKCP_MTU_DEF = 1400 */
	int mtu = (int)luaL_optinteger(L, 2, 1400);
	ikcp_setmtu(peer, mtu);
	return 0;
}

static int lua__waitsnd(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int cnt = ikcp_waitsnd(peer);
	lua_pushinteger(L, cnt);
	return 1;
}

static int lua__check(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	IUINT32 current = (IUINT32)luaL_checknumber(L, 2);
	IUINT32 interval = ikcp_check(peer, current);
	lua_pushnumber(L, interval);
	return 1;
}


static int lua__update(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	IUINT32 current = luaL_checknumber(L, 2);
	ikcp_update(peer, current);
	return 0;
}

static int lua__input(lua_State *L)
{
	size_t sz;
	ikcpcb *peer = CHECK_PEER(L, 1);
	const char * buffer = luaL_checklstring(L, 2, &sz);
	ikcp_input(peer, buffer, sz);
	return 0;
}

static int lua__sndbuf_count(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int cnt = ikcp_sndbuf_count(peer);
	lua_pushinteger(L, cnt);
	return 1;
}

static int lua__rcvbuf_count(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int cnt = ikcp_rcvbuf_count(peer);
	lua_pushinteger(L, cnt);
	return 1;
}

static int lua__peeksize(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int sz = ikcp_peeksize(peer);
	lua_pushinteger(L, sz);
	return 1;
}

static int lua__flush(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	ikcp_flush(peer);
	return 0;
}

static int lua__log(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	int mask = (int)luaL_checkinteger(L, 2);
	const char * msg = luaL_checkstring(L, 3);
	ikcp_log(peer, mask, "%s", msg);
	return 0;
}

static int lua__get_state(lua_State *L)
{
	ikcpcb *peer = CHECK_PEER(L, 1);
	lua_newtable(L);
#define XX(field) LUA_SET_PEER_STATE(L, -1, field, peer);
	PEER_FIELD_MAP(XX)
#undef XX
	return 1;
}

/* }} method */

static int opencls__peer(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"recv", lua__recv},
		{"send", lua__send},
		{"wndsize", lua__wndsize},
		{"nodelay", lua__nodelay},
		{"update", lua__update},
		{"input", lua__input},
		{"flush", lua__flush},
		{"setmtu", lua__setmtu},
		{"get_state", lua__get_state},
		{"peeksize", lua__peeksize},
		{"sndbuf_count", lua__sndbuf_count},
		{"rcvbuf_count", lua__rcvbuf_count},
		{"check", lua__check},
		{"waitsnd", lua__waitsnd},
		{"log", lua__log},
		{NULL, NULL},
	};
	luaL_newmetatable(L, LIKCP_PEER_NAME);
	luaL_newlib(L, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__gc);
	lua_setfield (L, -2, "__gc");
	return 1;
}

static int luac__register_logmask(lua_State *L)
{
	lua_newtable(L);
#define XX(name) LUA_SETFIELD(L, -1, #name, name);
	LIKCP_LOG_MAP(XX)
#undef XX
	return 1;
}

static int lua__clock(lua_State *L)
{
	lua_pushnumber(L, iclock());
	return 1;
}

int luaopen_lkcp(lua_State* L)
{
	luaL_Reg lfuncs[] = {
		{"new", lua__new},
		{"clock", lua__clock},
		{"sleep", lua__sleep},
		{NULL, NULL},
	};
	/* to save peer */
	lua_pushstring(L, LIKCP_PEER_MAP);
	lua_newtable(L);
	/* lua_setfield(L, LUA_REGISTRYINDEX, LIKCP_PEER_MAP); */
	lua_settable(L, LUA_REGISTRYINDEX);

	opencls__peer(L);
	luaL_newlib(L, lfuncs);
	luac__register_logmask(L);
	lua_setfield(L, -2, "LogMask");
	return 1;
}

