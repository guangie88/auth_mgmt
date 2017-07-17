const DEBOUNCE_MS = 500;

const catchFn = error => alert(JSON.stringify(error, null, 2));

const scrollTo = anchor => {
  const top = document.getElementById(anchor).offsetTop;
  window.scrollTo(0, top);
};

const getCurrentUrlWithoutParams = () => {
  return `${window.location.protocol}//${window.location.host}${window.location.pathname}`
};

Vue.component('wrong-msg', {
  props: ['msg'],
  template: `
    <div v-if="msg !== null" class="alert alert-danger alert-no-margin display-table full-width">
      <div class="display-table-cell glyph align-middle"><svg class="glyph align-middle"><image class="glyph" xlink:href="/images/x.svg" /></svg></div>
      <strong class="display-table-cell align-middle" v-text="msg"></strong>
    </div>
  `,
});

Vue.component('creds-listing', {
  props: ['disabled', 'creds'],
  template: `
    <div>
      <template v-for="(value, key) in creds">
        <!-- boolean -->
        <div v-if="typeof(value) === 'boolean'" class="form-group row">
          <label class="custom-control custom-checkbox">
            <input class="custom-control-input" :disabled="disabled" type="checkbox" v-model="creds[key]">
            <span class="custom-control-indicator"></span>
            <span class="custom-control-description" v-text="key"></span>
          </label>
        </div>

        <!-- string -->
        <div v-else-if="typeof(value) === 'string'" class="form-group row">
          <label :for="key" class="col-form-label col-sm-2" v-html="key"></label>
          <div class="col-sm-10">
            <input :id="key" class="form-control" :disabled="disabled" type="text" v-model="creds[key]">
          </div>
        </div>

        <!-- object -->
        <div v-else-if="value !== null && typeof(value) === 'object'">
          <div class="card vspacer">
            <div class="card-header" role="tab">
              <h5 class="mb-0" v-text="key"></h5>
            </div>

            <div :aria-labelledby="key" class="card-block" role="tabpanel">
              <creds-listing :disabled="disabled" :creds="value"></creds-listing>        
            </div>
          </div>
        </div>
      </template>
    </div>
  `,
});

const app = new Vue({
  // router,
  el: '#app',

  data: {
    // models
    adminTaskCreds: null,
    confirmNewPassword: null,
    confirmPassword: null,
    newPassword: null,
    selectedExchange: null,
    selectedUpdate: { username: null, password: null },
    toAddCreds: null,
    toDeleteUsers: null,
    toUpdateUsers: null,
    users: [],

    // models for error
    errorAddMsg: null,
    errorChangePasswordMsg: null,
    errorDeleteMsg: null,
    errorUpdateMsg: null,

    // model for previous action status
    prevActionMsg: null,
  },

  mounted() {
    axios.get('/info')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.adminTaskCreds = resp.data.data;
        }
      })
      .catch(catchFn);

    axios.get('/get_default_creds')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.toAddCreds = resp.data.data;
        }
      })

    axios.get('/get_users')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.users = _.sortBy(resp.data.data, user => user);

          this.toDeleteUsers = _.map(this.users, user => {
            return { username: user, delete: false };
          });

          this.toUpdateUsers = _.map(this.users, user => {
            return { username: user, selected: false };
          });
        }
      })
      .catch(catchFn);
  },

  methods: {
    changePassword: function(errAnchor) {
      axios.post('/change_password', { newPassword: this.newPassword })
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.href = `${getCurrentUrlWithoutParams()}?password`;
          } else {
            this.errorAddMsg = `Change password error: ${resp.data.status}`;
            scrollTo(errAnchor);
          }
        })
        .catch(catchFn);
    },

    addUser: function(errAnchor) {
      axios.post('/add_mapping', this.toAddCreds)
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.href = `${getCurrentUrlWithoutParams()}?add`;
          } else {
            this.errorAddMsg = `Add user error: ${resp.data.status}`;
            scrollTo(errAnchor);
          }
        })
        .catch(catchFn);
    },

    exchange: function(errAnchor) {
      axios.post('/exchange', this.selectedUpdate)
        .then(resp => {
          if (resp.data.status == 'ok') {
            this.selectedExchange = resp.data.data;
            this.errorUpdateMsg = null;
          } else {
            this.errorUpdateMsg = `Invalid retrieval: ${resp.data.status}`;
            this.selectedExchange = null;
            scrollTo(errAnchor);
          }
        })
        .catch(catchFn);
    },

    updateUser: function(errAnchor) {
      const toUpdateUser = {
        username: this.selectedUpdate.username,
        password: this.selectedUpdate.password,
        creds: this.selectedExchange,
      };

      axios.put('/update_mapping', toUpdateUser)
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.href = `${getCurrentUrlWithoutParams()}?update`;
          } else {
            this.errorUpdateMsg = `Update error: ${resp.data.status}`
            scrollTo(errAnchor);
          }
        })
        .catch(catchFn);
    },

    deleteUsers: function(errAnchor) {
      const confirmDeleteUserGroups = _.filter(this.toDeleteUsers, toDeleteUser => toDeleteUser.delete);
      const confirmDeleteUsernames = _.map(confirmDeleteUserGroups, confirmDeleteUserGroup => confirmDeleteUserGroup.username);

      // DELETE has a different API from POST
      axios.delete('/force_delete_mappings', { data: confirmDeleteUsernames, headers: { 'Content-Type': 'application/json' } })
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.href = `${getCurrentUrlWithoutParams()}?delete`;
          } else {
            this.errorDeleteMsg = `Delete user(s) error: ${resp.data.status}`;
            scrollTo(errAnchor);
          }
        })
        .catch(catchFn);
    },

    logout: function() {
      this.$cookies.remove('token', '/', window.location.hostname);
      window.location.href = '/';
    },

    pwDebounce: function(password, confirmPassword, msgKey) {
      if (password && confirmPassword) {
        if (password === confirmPassword) {
          this[msgKey] = null;
        } else {
          this[msgKey] = 'The passwords do not match!';
        }
      }
    },

    // must use function for this data context
    changePwDebounce: _.debounce(function() {
      this.pwDebounce(this.newPassword, this.confirmNewPassword, 'errorChangePasswordMsg');
    }, DEBOUNCE_MS),

    addPwDebounce: _.debounce(function() {
      this.pwDebounce(this.toAddCreds.password, this.confirmPassword, 'errorAddMsg');
    }, DEBOUNCE_MS),
  },
});