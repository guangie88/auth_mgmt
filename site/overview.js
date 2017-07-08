var Main = new Vue({
  el: '#overview',

  data: {
    adminTaskCreds: "Hello",

    // tableData: [{
    //   date: '2016-05-03',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }, {
    //   date: '2016-05-02',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }, {
    //   date: '2016-05-04',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }, {
    //   date: '2016-05-01',
    //   name: 'Tom',
    //   address: 'No. 189, Grove St, Los Angeles'
    // }]
  },

  mounted() {
    axios.get('/info')
      .then(resp => {
        console.log(resp);
        this.adminTaskCreds = resp.data;
      })
      .catch(error => alert(JSON.stringify(error)));
  },
});