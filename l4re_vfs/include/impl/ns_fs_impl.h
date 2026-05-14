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

// ns_fs_impl.h is compiled into both regular processes (where libc printf is
// available) and ldso (freestanding, no libc).  Gate printf behind the macro
// that ldso defines so the linker in the freestanding build doesn't complain.
#ifndef IS_IN_rtld
#  include <stdio.h>
#  define VFS_DBG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#  define VFS_DBG(fmt, ...) do {} while (0)
#endif

namespace L4Re { namespace Core {

// Zero-timeout probe via Meta::num_interfaces() (opcode 0, no args).
// Returns false immediately if the cap is unresponsive (sigma0, rtc blocked
// on IRQ, etc.) so callers can skip the slow interface()/supports() IPC.
static bool
meta_probe(l4_cap_idx_t cap) noexcept
{
  l4_utcb_t *u = l4_utcb();
  l4_msg_regs_t *mr = l4_utcb_mr_u(u);
  mr->mr[0] = 0;  // Meta::num_interfaces() — no input args
  l4_msgtag_t tag = l4_msgtag(L4_PROTO_META, 1, 0, 0);
  tag = l4_ipc_call(cap, u, tag,
                    l4_timeout(L4_IPC_TIMEOUT_0, L4_IPC_TIMEOUT_NEVER));
  return !l4_msgtag_has_error(tag);
}

static
Ref_ptr<L4Re::Vfs::File>
cap_to_vfs_object(L4::Cap<void> o, int *err)
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
  return factory->create(o);
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
Ns_dir::get_entry(const char *path, int /*flags*/, mode_t /*mode*/,
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

  cxx::Ref_ptr<L4Re::Vfs::File> fi = cap_to_vfs_object(file.get(), &err);
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
Env_dir::get_entry(const char *path, int /*flags*/, mode_t /*mode*/,
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

  cxx::Ref_ptr<L4Re::Vfs::File> fi = cap_to_vfs_object(file.get(), &err);
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
  tag = l4_ipc_call(e->cap, u, tag,
                    l4_timeout(L4_IPC_TIMEOUT_0, L4_IPC_TIMEOUT_NEVER));
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

ssize_t
Env_dir::getdents(char *buf, size_t sz) noexcept
{
  struct dirent64 *d = reinterpret_cast<struct dirent64 *>(buf);
  ssize_t ret = 0;

  while (d
         && _current_cap_entry
         && _current_cap_entry->flags != ~0UL)
    {
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
          VFS_DBG("[vfs:gd] entry '%s' cap=0x%lx\n",
                 _current_cap_entry->name, (unsigned long)_current_cap_entry->cap);
          if (check_type(_current_cap_entry, L4Re::Namespace::Protocol))
            d->d_type = DT_DIR;
          else if (check_type(_current_cap_entry, L4Re::Dataspace::Protocol))
            d->d_type = DT_REG;
          else
            d->d_type = DT_UNKNOWN;
          VFS_DBG("[vfs:gd] '%s' -> d_type=%d\n",
                 _current_cap_entry->name, d->d_type);
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
