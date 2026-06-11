/*
 * (c) 2010 Adam Lackorzynski <adam@os.inf.tu-dresden.de>,
 *          Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#include "ns_fs.h"

#include <l4/re/dataspace>
#include <l4/re/util/env_ns>
#include <l4/re/unique_cap>
#include <l4/sys/ipc.h>
#include <dirent.h>
#include <fcntl.h>

// ns_fs_impl.h is compiled into both regular processes (where libc printf is
// available) and ldso (freestanding, no libc).  Gate printf behind the macro
// that ldso defines so the linker in the freestanding build doesn't complain.
#ifndef IS_IN_rtld
#  include <stdio.h>
#endif
// VFS trace messages disabled for production; define L4_VFS_DEBUG to re-enable
#ifdef L4_VFS_DEBUG
#  define VFS_DBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#  define VFS_DBG(fmt, ...) do {} while (0)
#endif

namespace L4Re { namespace Core {

// Timeout for Meta probes sent to initial caps.  The *send* timeout is 0 so
// the call fails fast when the peer is not in a receive-wait.  But if the peer
// *is* receiving yet never replies — e.g. sigma0, which accepts the message
// and sends no answer — an L4_IPC_TIMEOUT_NEVER *receive* would block the
// caller forever.  That is the probabilistic `cd` / Tab-completion hang: it
// fires only in the window where an unresponsive cap happens to be in
// receive-wait at probe time.  A finite receive timeout bounds it.  50 ms is
// far above the worst-case Meta round-trip (~3 ms under load per cyclictest),
// so a responsive VFS namespace server is never falsely timed out, while a
// silent cap is abandoned after 50 ms instead of hanging the shell.
enum { Vfs_meta_rcv_us = 50000 };

static inline l4_timeout_t
meta_call_timeout() noexcept
{
  return l4_timeout(L4_IPC_TIMEOUT_0, l4_timeout_from_us(Vfs_meta_rcv_us));
}

// Bounded probe via Meta::num_interfaces() (opcode 0, no args).  Returns false
// if the cap is unresponsive — either not in a receive-wait (send fails fast)
// or in receive-wait but not replying (receive times out after 50 ms) — so
// callers can skip the slow interface()/supports() IPC without risking a hang.
static bool
meta_probe(l4_cap_idx_t cap) noexcept
{
  l4_utcb_t *u = l4_utcb();
  l4_msg_regs_t *mr = l4_utcb_mr_u(u);
  mr->mr[0] = 0;  // Meta::num_interfaces() — no input args
  l4_msgtag_t tag = l4_msgtag(L4_PROTO_META, 1, 0, 0);
  tag = l4_ipc_call(cap, u, tag, meta_call_timeout());
  return !l4_msgtag_has_error(tag);
}

static
Ref_ptr<L4Re::Vfs::File>
cap_to_vfs_object(L4::Cap<void> o, int *err, int oflags = 0)
{
  L4::Cap<L4::Meta> m = L4::cap_reinterpret_cast<L4::Meta>(o);
  *err = -ENOPROTOOPT;
  VFS_DBG("[vfs:co] probe cap=0x%lx\n", (unsigned long)m.cap());
  if (!meta_probe(m.cap()))
    {
      VFS_DBG("[vfs:co] probe FAIL cap=0x%lx\n", (unsigned long)m.cap());
      return Ref_ptr<L4Re::Vfs::File>();
    }
  VFS_DBG("[vfs:co] probe ok, interface() cap=0x%lx\n", (unsigned long)m.cap());
  long proto = 0;
  char name_buf[256];
  L4::Ipc::String<char> name(sizeof(name_buf), name_buf);
  l4_ret_t r = l4_error(m->interface(0, &proto, &name));
  VFS_DBG("[vfs:co] interface() cap=0x%lx r=%ld proto=%ld\n",
         (unsigned long)m.cap(), (long)r, proto);
  if (r < 0)
    return Ref_ptr<L4Re::Vfs::File>();

  *err = -EPROTO;
  Ref_ptr<L4Re::Vfs::File_factory> factory;

  if (proto != 0)
    factory = L4Re::Vfs::vfs_ops->get_file_factory(proto);

  if (!factory)
    factory = L4Re::Vfs::vfs_ops->get_file_factory(name.data);

  if (!factory)
    return Ref_ptr<L4Re::Vfs::File>();

  *err = -ENOMEM;
  Ref_ptr<L4Re::Vfs::File> f = factory->create(o);

  // Apply open-time flags the VFS framework does not handle itself (openat()
  // only forwards them to get_entry).  These are generic File ops: backends
  // that don't support them (read-only files, namespaces) reject/ignore
  // harmlessly, so this stays protocol-agnostic.
  if (f)
    {
      if ((oflags & O_TRUNC) && (oflags & O_ACCMODE) != O_RDONLY)
        f->ftruncate(0);
      if (oflags & O_APPEND)
        f->set_status_flags(O_APPEND);
    }

  return f;
}


int
Ns_dir::get_ds(const char *path, L4Re::Unique_cap<L4Re::Dataspace> *ds) noexcept
{
  auto file = L4Re::make_unique_cap<L4Re::Dataspace>(L4Re::virt_cap_alloc);

  if (!file.is_valid())
    return -ENOMEM;

  int err = _ns->query(path, file.get());

  if (err < 0)
    return -ENOENT;

  *ds = cxx::move(file);
  return err;
}

int
Ns_dir::get_entry(const char *path, int flags, mode_t /*mode*/,
                  Ref_ptr<L4Re::Vfs::File> *f) noexcept
{
  if (!*path)
    {
      *f = cxx::ref_ptr(this);
      return 0;
    }

  L4Re::Unique_cap<Dataspace> file;
  int err = get_ds(path, &file);

  if (err < 0)
    return -ENOENT;

  cxx::Ref_ptr<L4Re::Vfs::File> fi = cap_to_vfs_object(file.get(), &err, flags);
  if (!fi)
    return err;

  file.release();
  *f = cxx::move(fi);
  return 0;
}

int
Ns_dir::faccessat(const char *path, int mode, int /*flags*/) noexcept
{
  auto tmpcap = L4Re::make_unique_cap<void>(L4Re::virt_cap_alloc);

  if (!tmpcap.is_valid())
    return -ENOMEM;

  if (_ns->query(path, tmpcap.get()))
    return -ENOENT;

  if (mode & W_OK)
    return -EACCES;

  return 0;
}

int
Ns_dir::fstat(struct stat64 *b) const noexcept
{
  b->st_dev = 1;
  b->st_ino = 1;
  b->st_mode = S_IRWXU | S_IFDIR;
  b->st_nlink = 0;
  b->st_uid = 0;
  b->st_gid = 0;
  b->st_rdev = 0;
  b->st_size = 0;
  b->st_blksize = 0;
  b->st_blocks = 0;
  b->st_atime = 0;
  b->st_mtime = 0;
  b->st_ctime = 0;
  return 0;
}

ssize_t
Ns_dir::getdents(char *buf, size_t dest_sz) noexcept
{
  struct dirent64 *dest = reinterpret_cast<struct dirent64 *>(buf);
  ssize_t ret = 0;
  l4_addr_t infoaddr;
  size_t infosz;

  L4Re::Unique_cap<Dataspace> dirinfofile;
  int err = get_ds(".dirinfo", &dirinfofile);
  if (err)
    return 0;

  infosz = dirinfofile->size();
  if (infosz <= 0)
    return 0;

  infoaddr = L4_PAGESIZE;
  err = L4Re::Env::env()->rm()->attach(&infoaddr, infosz,
                                       Rm::F::Search_addr | Rm::F::R,
                                       dirinfofile.get(), 0);
  if (err < 0)
    return 0;

  char *p   = reinterpret_cast<char *>(infoaddr) + _current_dir_pos;
  char *end = reinterpret_cast<char *>(infoaddr) + infosz;

  char *current_dirinfo_entry = p;
  while (dest && p < end)
    {
      // parse lines of dirinfofile
      long len = 0;
      for (; p < end && *p >= '0' && *p <= '9'; ++p)
        {
          len *= 10;
          len += *p - '0';
        }

      if (len == 0)
        break;

      if (p == end)
        break;

      if (*p != ':')
        break;
      p++; // skip colon

      if (p + len >= end)
        break;

      unsigned l = len + 1;
      if (l > sizeof(dest->d_name))
        l = sizeof(dest->d_name);

      unsigned n = offsetof (struct dirent64, d_name) + l;
      n = (n + sizeof(long) - 1) & ~(sizeof(long) - 1);

      if (n > dest_sz)
        break;

      dest->d_ino = 1;
      dest->d_off = 0;
      memcpy(dest->d_name, p, l - 1);
      dest->d_name[l - 1] = 0;
      dest->d_reclen = n;
      dest->d_type   = DT_UNKNOWN;
      ret += n;
      dest_sz -= n;

      // next entry
      dest = reinterpret_cast<struct dirent64 *>
               (reinterpret_cast<unsigned long>(dest) + n);

      // next infodirfile line
      p += len;
      // Optional type tag appended directly after name, before newline:
      // 'd' = directory (DT_DIR), 'f' = regular file (DT_REG).
      // Absent = DT_UNKNOWN (backward-compatible with old format).
      if (p < end && (*p == 'd' || *p == 'f')) {
        dest->d_type = (*p == 'd') ? DT_DIR : DT_REG;
        p++;
      }
      while (p < end && *p && (*p == '\n' || *p == '\r'))
        p++;

      current_dirinfo_entry = p;
    }

  _current_dir_pos = current_dirinfo_entry - reinterpret_cast<char *>(infoaddr);

  if (!ret) // hack since we should only reset this at open times
    _current_dir_pos = 0;

  L4Re::Env::env()->rm()->detach(infoaddr, 0);

  return ret;
}

int
Env_dir::get_ds(const char *path, L4Re::Unique_cap<L4Re::Dataspace> *ds) noexcept
{
  while (*path == '/')
    ++path;
  Vfs::Path p(path);
  Vfs::Path first = p.strip_first();

  if (first.empty())
    return -ENOENT;

  L4::Cap<L4Re::Namespace>
    c = _env->get_cap<L4Re::Namespace>(first.path(), first.length());

  if (!c.is_valid())
    return -ENOENT;

  if (p.empty())
    {
      *ds = L4Re::Unique_cap<L4Re::Dataspace>(L4::cap_reinterpret_cast<L4Re::Dataspace>(c));
      return 0;
    }

  auto file = L4Re::make_unique_cap<L4Re::Dataspace>(L4Re::virt_cap_alloc);

  if (!file.is_valid())
    return -ENOMEM;

  int err = c->query(p.path(), p.length(), file.get());

  if (err < 0)
    return -ENOENT;

  *ds = cxx::move(file);
  return err;
}

int
Env_dir::get_entry(const char *path, int flags, mode_t /*mode*/,
                   Ref_ptr<L4Re::Vfs::File> *f) noexcept
{
  if (!*path)
    {
      *f = cxx::ref_ptr(this);
      return 0;
    }

  L4Re::Unique_cap<Dataspace> file;
  int err = get_ds(path, &file);

  if (err < 0)
    return -ENOENT;

  cxx::Ref_ptr<L4Re::Vfs::File> fi = cap_to_vfs_object(file.get(), &err, flags);
  if (!fi)
    return err;

  file.release();
  *f = cxx::move(fi);
  return 0;
}

int
Env_dir::faccessat(const char *path, int mode, int /*flags*/) noexcept
{
  while (*path == '/')
    ++path;
  Vfs::Path p(path);
  Vfs::Path first = p.strip_first();

  if (first.empty())
    return -ENOENT;

  L4::Cap<L4Re::Namespace>
    c = _env->get_cap<L4Re::Namespace>(first.path(), first.length());

  if (!c.is_valid())
    return -ENOENT;

  if (p.empty())
    {
      if (mode & W_OK)
	return -EACCES;

      return 0;
    }

  auto tmpcap = L4Re::make_unique_cap<void>(L4Re::virt_cap_alloc);

  if (!tmpcap.is_valid())
    return -ENOMEM;

  if (c->query(p.path(), p.length(), tmpcap.get()))
    return -ENOENT;

  if (mode & W_OK)
    return -EACCES;

  return 0;
}

bool
Env_dir::check_type(Env::Cap_entry const *e, long protocol) noexcept
{
  VFS_DBG("[vfs:ct] '%s' cap=0x%lx proto=0x%lx\n",
         e->name, (unsigned long)e->cap, (unsigned long)protocol);
  l4_utcb_t *u = l4_utcb();
  l4_msg_regs_t *mr = l4_utcb_mr_u(u);
  mr->mr[0] = 2;                      // Meta::supports() — 3rd in Rpcs (0=num_interfaces,1=interface,2=supports)
  mr->mr[1] = (l4_umword_t)protocol;
  l4_msgtag_t tag = l4_msgtag(L4_PROTO_META, 2, 0, 0);
  // Finite receive timeout — same reasoning as meta_probe(): a silent cap in
  // receive-wait must not block getdents()/check_type() forever.
  tag = l4_ipc_call(e->cap, u, tag, meta_call_timeout());
  if (l4_msgtag_has_error(tag))
    {
      VFS_DBG("[vfs:ct] '%s' IPC-err=0x%lx -> false\n",
             e->name, l4_utcb_tcr_u(u)->error);
      return false;
    }
  bool result = l4_msgtag_label(tag) > 0;
  VFS_DBG("[vfs:ct] '%s' label=%ld -> %d\n",
         e->name, l4_msgtag_label(tag), (int)result);
  return result;
}

int
Env_dir::fstat(struct stat64 *b) const noexcept
{
  b->st_dev = 1;
  b->st_ino = 1;
  b->st_mode = S_IRWXU | S_IFDIR;
  b->st_nlink = 0;
  b->st_uid = 0;
  b->st_gid = 0;
  b->st_rdev = 0;
  b->st_size = 0;
  b->st_blksize = 0;
  b->st_blocks = 0;
  b->st_atime = 0;
  b->st_mtime = 0;
  b->st_ctime = 0;
  return 0;
}

// Local string compare: ldso links a minimal libc without strcmp().
static inline bool env_dir_str_eq(char const *a, char const *b) noexcept
{
  while (*a && *a == *b) { ++a; ++b; }
  return *a == *b;
}

bool
Env_dir::name_is_mount(char const *name) noexcept
{
  cxx::Ref_ptr<L4Re::Vfs::Mount_tree> mt = mount_tree();
  if (!mt)
    return false;
  for (cxx::Ref_ptr<L4Re::Vfs::Mount_tree> c = mt->first_child();
       c; c = c->next_sibling())
    {
      if (!c->mount())
        continue;
      char const *pn = c->path_name();
      if (pn && env_dir_str_eq(pn, name))
        return true;
    }
  return false;
}

ssize_t
Env_dir::getdents(char *buf, size_t sz) noexcept
{
  struct dirent64 *d = reinterpret_cast<struct dirent64 *>(buf);
  ssize_t ret = 0;

  while (d
         && _current_cap_entry
         && _current_cap_entry->flags != ~0UL)
    {
      // Only browsable namespaces are listed at the environment root (as
      // directories).  Everything else — service-gate caps (spawnd, authd,
      // syslogd), device/bus caps (rtc, fb, input; note a vbus also answers the
      // Dataspace protocol, so a plain ns||ds test would leak it), and bare
      // dataspaces — is reached programmatically via get_cap() and surfaced
      // under /dev or /svc, not as a loose, uncategorised root entry.  Hiding
      // them from the listing does not affect opening them by name.
      if (!check_type(_current_cap_entry, L4Re::Namespace::Protocol))
        {
          VFS_DBG("[vfs:gd] skip non-namespace cap '%s'\n",
                 _current_cap_entry->name);
          _current_cap_entry++;
          continue;
        }
      // Dedup: a VFS mount shadows the cap of the same name for path lookup, so
      // list it once (in the mount phase below), not twice.
      if (name_is_mount(_current_cap_entry->name))
        {
          VFS_DBG("[vfs:gd] skip mount-shadowed cap '%s'\n",
                 _current_cap_entry->name);
          _current_cap_entry++;
          continue;
        }

      unsigned l = strlen(_current_cap_entry->name) + 1;
      if (l > sizeof(d->d_name))
        l = sizeof(d->d_name);

      unsigned n = offsetof (struct dirent64, d_name) + l;
      n = (n + sizeof(long) - 1) & ~(sizeof(long) - 1);

      if (n <= sz)
        {
          d->d_ino = 1;
          d->d_off = 0;
          memcpy(d->d_name, _current_cap_entry->name, l);
          d->d_name[l - 1] = 0;
          d->d_reclen = n;
          d->d_type = DT_DIR;   // only namespaces reach here
          VFS_DBG("[vfs:gd] entry '%s' -> d_type=DIR\n",
                 _current_cap_entry->name);
          ret += n;
          sz  -= n;
          d    = reinterpret_cast<struct dirent64 *>
                   (reinterpret_cast<unsigned long>(d) + n);
          _current_cap_entry++;
        }
      else
        return ret;
    }

  /* After cap entries, emit VFS mount-point children (e.g. "dev"). */
  if (!ret && mount_tree() && !_mt_done)
    {
      /* Initialise mount-tree iteration on first entry of this phase. */
      if (!_mt_child)
        _mt_child = mount_tree()->first_child();

      while (_mt_child)
        {
          /* Only emit nodes that actually have something mounted on them. */
          if (!_mt_child->mount())
            { _mt_child = _mt_child->next_sibling(); continue; }

          char const *name = _mt_child->path_name();
          if (!name)
            { _mt_child = _mt_child->next_sibling(); continue; }

          unsigned l = strlen(name) + 1;
          if (l > sizeof(d->d_name)) l = sizeof(d->d_name);
          unsigned n = offsetof(struct dirent64, d_name) + l;
          n = (n + sizeof(long) - 1) & ~(sizeof(long) - 1);

          if (n > sz)
            return ret; /* buffer full, caller will retry */

          d->d_ino    = 2;
          d->d_off    = 0;
          d->d_reclen = (unsigned short)n;
          d->d_type   = DT_DIR;
          memcpy(d->d_name, name, l);
          d->d_name[l - 1] = 0;
          ret += n;
          sz  -= n;
          d = reinterpret_cast<struct dirent64 *>
                (reinterpret_cast<unsigned long>(d) + n);

          _mt_child = _mt_child->next_sibling();
          if (!_mt_child)
            _mt_done = true; /* last sibling consumed */
          return ret; /* yield one entry per call, matching existing pattern */
        }
      _mt_done = true; /* all mount children emitted (skipped or zero) */
    }

  /* bit of a hack because we should only (re)set this when opening the dir */
  if (!ret)
    {
      _current_cap_entry = _env->initial_caps();
      _mt_child = nullptr;
      _mt_done = false;
    }

  return ret;
}

}}
