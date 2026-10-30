<script setup>
defineProps({
  modelValue: { type: Boolean, default: false },
  name: { type: String, default: '' },
  id: { type: String, default: '' },
  label: { type: String, default: '' },
  size: { type: String, default: 'default' }, // 'default' | 'lg'
  disabled: { type: Boolean, default: false },
})

defineEmits(['update:modelValue', 'change'])
</script>

<template>
  <label
    :class="['toggle-wrapper', `size-${size}`, { 'is-active': modelValue, 'is-disabled': disabled }]"
    :for="id || undefined"
  >
    <input
      :id="id || undefined"
      type="checkbox"
      role="switch"
      :name="name || undefined"
      :checked="modelValue"
      :disabled="disabled"
      :aria-checked="modelValue"
      :aria-label="label || undefined"
      class="toggle-input"
      @change="$emit('update:modelValue', $event.target.checked); $emit('change', $event.target.checked)"
    />
    <span class="toggle-track" aria-hidden="true">
      <span class="toggle-thumb" />
    </span>
  </label>
</template>

<style scoped>
.toggle-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
  cursor: pointer;
  user-select: none;
  vertical-align: middle;
}

.toggle-wrapper.is-disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.toggle-input {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.toggle-track {
  display: inline-flex;
  align-items: center;
  position: relative;
  border-radius: 999px;
  background: var(--surface-3);
  border: 1px solid var(--line-strong);
  transition: background-color 0.2s cubic-bezier(0.16, 1, 0.3, 1),
              border-color 0.2s cubic-bezier(0.16, 1, 0.3, 1),
              box-shadow 0.2s ease;
  box-sizing: border-box;
}

/* Default Size */
.size-default .toggle-track {
  width: 44px;
  height: 24px;
  padding: 2px;
}

.size-default .toggle-thumb {
  width: 18px;
  height: 18px;
}

.size-default.is-active .toggle-thumb {
  transform: translateX(20px);
}

/* Large / Dominant Size */
.size-lg .toggle-track {
  width: 54px;
  height: 30px;
  padding: 3px;
}

.size-lg .toggle-thumb {
  width: 22px;
  height: 22px;
}

.size-lg.is-active .toggle-thumb {
  transform: translateX(24px);
}

.toggle-thumb {
  display: block;
  border-radius: 50%;
  background: var(--text-2);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
  transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1),
              background-color 0.2s ease;
}

.toggle-wrapper:hover:not(.is-disabled) .toggle-track {
  border-color: #4a4e57;
}

.toggle-wrapper:hover:not(.is-disabled) .toggle-thumb {
  background: #ffffff;
}

.toggle-wrapper.is-active .toggle-track {
  background: var(--ok);
  border-color: var(--ok);
}

.toggle-wrapper.is-active .toggle-thumb {
  background: #0a0b0d;
}

.toggle-input:focus-visible + .toggle-track {
  outline: 2px solid var(--text-2);
  outline-offset: 3px;
}
</style>
