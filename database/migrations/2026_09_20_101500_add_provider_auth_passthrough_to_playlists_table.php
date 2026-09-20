<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('playlists', function (Blueprint $table) {
            $table->boolean('provider_auth_passthrough_enabled')
                ->default(false);

            $table->boolean('provider_auth_passthrough_live')
                ->default(true);

            $table->boolean('provider_auth_passthrough_vod')
                ->default(false);

            $table->boolean('provider_auth_passthrough_series')
                ->default(false);
        });

        /*
         * /player_api.php has no playlist identifier. Therefore only one
         * passthrough playlist may exist in the whole installation.
         *
         * PostgreSQL is the current recommended production database and
         * SQLite is used by the project's tests. Both support partial indexes.
         */
        $driver = DB::connection()->getDriverName();

        if (in_array($driver, ['pgsql', 'sqlite'], true)) {
            DB::statement(
                'CREATE UNIQUE INDEX playlists_provider_auth_passthrough_singleton
                 ON playlists (provider_auth_passthrough_enabled)
                 WHERE provider_auth_passthrough_enabled = TRUE'
            );
        }
    }

    public function down(): void
    {
        $driver = DB::connection()->getDriverName();

        if (in_array($driver, ['pgsql', 'sqlite'], true)) {
            DB::statement(
                'DROP INDEX IF EXISTS playlists_provider_auth_passthrough_singleton'
            );
        }

        Schema::table('playlists', function (Blueprint $table) {
            $table->dropColumn([
                'provider_auth_passthrough_enabled',
                'provider_auth_passthrough_live',
                'provider_auth_passthrough_vod',
                'provider_auth_passthrough_series',
            ]);
        });
    }
};
