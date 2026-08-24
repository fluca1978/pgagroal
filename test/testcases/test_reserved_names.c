/*
 * Copyright (C) 2026 The pgagroal community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 *    of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *    list of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 *    be used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <mctf.h>
#include <utils.h>

MCTF_TEST(test_utils_reserved_username)
{
   MCTF_ASSERT(!pgagroal_is_username_reserved(NULL), cleanup, "NULL username should not be reserved");
   MCTF_ASSERT(!pgagroal_is_username_reserved(""), cleanup, "empty username should not be reserved");

   MCTF_ASSERT(pgagroal_is_username_reserved("all"), cleanup, "'all' should be reserved");
   MCTF_ASSERT(pgagroal_is_username_reserved("sameuser"), cleanup, "'sameuser' should be reserved");

   MCTF_ASSERT(!pgagroal_is_username_reserved("postgres"), cleanup, "'postgres' should not be reserved");
   MCTF_ASSERT(!pgagroal_is_username_reserved("app_user"), cleanup, "'app_user' should not be reserved");

cleanup:
   MCTF_FINISH();
}

MCTF_TEST(test_utils_reserved_database)
{
   MCTF_ASSERT(!pgagroal_is_database_reserved(NULL), cleanup, "NULL database should not be reserved");
   MCTF_ASSERT(!pgagroal_is_database_reserved(""), cleanup, "empty database should not be reserved");

   MCTF_ASSERT(pgagroal_is_database_reserved("all"), cleanup, "'all' should be reserved");
   MCTF_ASSERT(pgagroal_is_database_reserved("replication"), cleanup, "'replication' should be reserved");

   MCTF_ASSERT(!pgagroal_is_database_reserved("postgres"), cleanup, "'postgres' should not be reserved");
   MCTF_ASSERT(!pgagroal_is_database_reserved("appdb"), cleanup, "'appdb' should not be reserved");

cleanup:
   MCTF_FINISH();
}
