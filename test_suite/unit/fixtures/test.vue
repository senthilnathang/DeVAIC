<template>
  <div>
    <!-- Should be detected by vue-v-html-xss -->
    <div v-html="userContent"></div>
    <div v-html="item.htmlData"></div>
    <div v-html="getHTML()"></div>
    <div v-html="'<p>Static but still caught</p>' + dynamicPart"></div>
    <div v-html="`Template literal with ${dynamicData}`"></div>

    <!-- This is a literal, should also be caught by the broad rule -->
    <div v-html="'<strong>Static HTML</strong>'"></div>

    <!-- Safe usage (though not using v-html) -->
    <div>{{ userContent }}</div>
  </div>
</template>

<script>
export default {
  name: 'TestVueComponent',
  data() {
    return {
      userContent: '<script>alert("xss")</script>',
      item: {
        htmlData: '<span>Item HTML</span>'
      },
      dynamicPart: '<img src=x onerror=alert(1)>',
      dynamicData: '<em>Dynamic Content</em>'
    };
  },
  methods: {
    getHTML() {
      return '<a href="javascript:alert(2)">Click me</a>';
    }
  }
};
</script>

<style scoped>
div {
  margin: 10px;
  padding: 10px;
  border: 1px solid #ccc;
}
</style>
