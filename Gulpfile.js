var gulp = require('gulp');
var concat = require('gulp-concat');
var rename = require('gulp-rename');
var uglify = require('gulp-uglify');

gulp.task('scripts', function() {
  return gulp.src([
    'src/crypto-js/crypto.js',
    'src/crypto-js/sha256.js',
    'src/crypto-js/ripemd160.js',
    'src/jsbn/prng4.js',
    'src/jsbn/rng.js',
    'src/jsbn/jsbn.js',
    'src/jsbn/jsbn2.js',

    'src/jsbn/ec.js',
    'src/jsbn/sec.js',
    'src/events/eventemitter.js',
    'src/bitcoin.js',
    'src/util.js',
    'src/base58.js',

    'src/address.js',
    'src/ecdsa.js',
    'src/eckey.js',
    'src/opcode.js',
    'src/script.js',
    'src/transaction.js',

    'src/wallet.js',
    'src/txdb.js'
  ])
    .pipe(concat('bitcoinjs.js'))
    .pipe(gulp.dest('./build'))
    .pipe(rename('bitcoinjs-min.js'))
    .pipe(uglify())
    .pipe(gulp.dest('./build'));
});

// The default task (called when you run `gulp`)
gulp.task('default', function() {
  gulp.run('scripts');

  // Watch files and run tasks if they change
  gulp.watch('src/**/*.js', function() {
    gulp.run('scripts');
  });
});