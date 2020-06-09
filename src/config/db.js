
const mongoose = require('mongoose');

mongoose.connect(process.env.DATABASE_URI, { useNewUrlParser: true, useUnifiedTopology:true, useFindAndModify:false })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(e => {
    console.error(e);
  })

module.exports = mongoose;


