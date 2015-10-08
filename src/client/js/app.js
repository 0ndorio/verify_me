/// Configure loading modules from the lib directory,
/// expect for 'app' ones, which are in a sibling.
requirejs.config({
   baseUrl: 'js/lib',
   paths: {
      app: '../app'
   },
   shim: {
   }
});

/// Start loading the main app file.
requirejs(['app/main']);